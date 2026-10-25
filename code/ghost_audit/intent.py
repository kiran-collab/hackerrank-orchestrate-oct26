"""Does the request text authorize deletion?

Deterministic multilingual rules decide clear cases, in this order:

  1. explicit "keep / do not delete" language  -> NOT_DELETE  (beats any deletion word)
  2. deletion wording that is not an erasure request is masked out first:
       - negated within the same clause ("I don't want my account deleted")
       - hypothetical or how-to questions ("what happens if I delete...", "how do I delete...")
       - deleting a single field ("delete my old phone number and add the new one")
       - marketing removal ("remove me from the newsletter")
  3. remaining erasure vocabulary (any supported language) or a request to verify/finish a
     prior deletion                              -> DELETE
  4. other privacy actions (access, export, correction, opt-out, login help) -> NOT_DELETE
  5. otherwise                                   -> AMBIGUOUS

AMBIGUOUS never authorizes deletion by itself: the optional LLM classifier decides it when
enabled; without one the agent treats it as NOT_DELETE, because a wrong deletion is
destructive while a missed one is recoverable.
"""

from __future__ import annotations

import re

KEEP = re.compile(
    r"not asking for deletion|not a request to (erase|delete)|do not (close|delete)|don'?t (delete|close)"
    r"|without (removing|deleting)|leave (the|my) (account|profile)|keep the account|keep my account"
    r"|continue (using|to use)|still (need|want|use) (the|this|my)? ?account|marketing lists only"
    r"|leave .{0,40} in place|information request|please keep the account",
    re.I,
)

_ERASE_WORD = (r"delet\w*|eras\w*|remov\w*|clos\w*")

# Masks: spans that contain deletion words but are not a request to erase the account or data.
NEGATED = re.compile(rf"\b(don'?t|do not|never|doesn'?t|won'?t)\b[^.,;:!?]{{0,40}}?\b({_ERASE_WORD})", re.I)
HYPOTHETICAL = re.compile(
    rf"\b(what (happens|would happen)|what if|if i (were to |was to )?|in case i|how (do|can|would) i|"
    rf"is it possible to|can i)\b[^.;!?]{{0,60}}?\b({_ERASE_WORD})[^.;!?]*\?", re.I)
FIELD_ONLY = re.compile(
    rf"\b({_ERASE_WORD})\b\s+(my |the |our )?(old |previous |current |second |extra )?"
    rf"(phone( number)?|mobile( number)?|number|address|shipping address|billing address|card|payment method|"
    rf"nickname|photo|picture|avatar)\b", re.I)
MARKETING = re.compile(
    rf"\b({_ERASE_WORD})\b\s+(me|my (email|address))\s+from\s+(the |your |all )?"
    rf"(newsletter|mailing list|marketing|promotional|promotions|emails?|list)", re.I)

ERASE = re.compile(
    r"\b(delet\w*|eras\w*|remov\w*|clean\w* .{0,40}\bout\b|close\w* (my|this|the) account|closed my account"
    r"|disconnected my account|account (itself |page )?is gone|no longer need this account|get rid of)\b"
    r"|exclus[aã]o|elimin(ar|aci[oó]n|ate|are)|suppression|supprim|lösch|verwijder|usuń|usun|hapus|xóa|sil\b"
    r"|cancell?\w* (il|la|i|le) (mio|mia|miei|mie)? ?(account|profilo|dati)"
    r"|삭제|削除|удал|删除|注销|刪除|حذف|हटा|डिलीट",
    re.I,
)
# Requests to verify or finish a deletion already asked for: these authorize the audit.
VERIFY_DELETION = re.compile(
    r"\b(confirm|verify|check|audit|make sure)\b[^.]{0,80}\b(gone|deleted|removed|erased|closed|no longer exists?)\b"
    r"|\b(profile|account) is gone\b|\baccount (was|has been) deleted\b|\bstill exist(s|ed)?\b",
    re.I,
)
OTHER_ACTION = re.compile(
    r"\b(update|replace|correct|change|download|copy of|portable|unsubscribe|stop (the )?(promotional|marketing)"
    r"|reset|what personal information|access my|add the new)\b",
    re.I,
)


def _mask(text: str) -> str:
    for rx in (NEGATED, HYPOTHETICAL, FIELD_ONLY, MARKETING):
        text = rx.sub(" ", text)
    return text


def classify(text: str) -> str:
    """Returns 'DELETE', 'NOT_DELETE' or 'AMBIGUOUS'."""
    if KEEP.search(text):
        return "NOT_DELETE"
    rest = _mask(text)
    if ERASE.search(rest) or VERIFY_DELETION.search(rest):
        return "DELETE"
    if OTHER_ACTION.search(text) or rest != text:
        # Only non-erasure actions remain (including deletion words we masked as negated,
        # hypothetical, field-level, or marketing).
        return "NOT_DELETE"
    return "AMBIGUOUS"
