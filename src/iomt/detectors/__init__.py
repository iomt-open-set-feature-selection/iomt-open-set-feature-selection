from iomt.detectors.conformal_e import ConformalE
from iomt.detectors.cusum import Cusum
from iomt.detectors.threshold import Threshold


def make(name: str, cfg: dict):
    from iomt import protocol as P
    if name == "conformal_e":
        return ConformalE(P.get(cfg, "detectors.conformal_e.thetas", [0.15, 0.30, 0.50, 0.75, 1.0]),
                          P.get(cfg, "detectors.conformal_e.rho", 0.5))
    if name == "cusum":
        return Cusum(P.get(cfg, "detectors.cusum.drift_k", 0.5))
    if name == "threshold":
        return Threshold()
    raise ValueError(name)
