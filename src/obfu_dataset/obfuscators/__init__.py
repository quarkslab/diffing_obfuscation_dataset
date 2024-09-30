from obfu_dataset.types import Obfuscator, ObPass
from obfu_dataset.obfuscators.ollvm import OLLVM_PASS
from obfu_dataset.obfuscators.tigress import TIGRESS_PASS



def supported_passes(obfuscator: Obfuscator) -> list[ObPass]:
    match obfuscator:
        case Obfuscator.TIGRESS:
            return TIGRESS_PASS
        case Obfuscator.OLLVM:
            return OLLVM_PASS
