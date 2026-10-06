"""Attack corpus, mutators and attackers (defensive use only; sandbox-only payloads)."""
from .attackers import Attacker, BlindMutator, MutatingAttacker, ScriptedAttacker
from .corpus import FAMILIES, PARAPHRASES, base_corpus, build_attack, instruction
from .mutators import ALL_MUTATIONS, MUTATORS, mutate, variants

__all__ = ["Attacker", "BlindMutator", "MutatingAttacker", "ScriptedAttacker", "FAMILIES",
           "PARAPHRASES", "base_corpus", "build_attack", "instruction", "ALL_MUTATIONS",
           "MUTATORS", "mutate", "variants"]


def __getattr__(name):
    # LLMAttacker needs the optional [llm] extra (pydantic, pydantic-ai); import it only on demand
    # so `import whetstone.attacks` keeps working on a base install.
    if name == "LLMAttacker":
        from .llm_attacker import LLMAttacker
        return LLMAttacker
    raise AttributeError(name)
