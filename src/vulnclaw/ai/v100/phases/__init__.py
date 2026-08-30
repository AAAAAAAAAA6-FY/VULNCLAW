# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Phase implementation bindings for :class:`V100Orchestrator`."""
from types import MethodType
from . import phases_executor as _executor
from . import phases_recon as _recon
from . import phases_report as _report
from . import phases_taskgen as _taskgen
from . import phases_verify as _verify
_PHASES = (_recon, _taskgen, _executor, _verify, _report)
_STATIC_METHODS = {"_safe_parse_bundle_json", "_severity_verify_plan", "_should_upgrade_low_info"}
def bind_phase_methods(orchestrator) -> None:
    """Bind phase functions as instance methods while preserving ``self`` calls."""
    for phase in _PHASES:
        for name in phase.__all__:
            implementation = getattr(phase, name)
            if name in _STATIC_METHODS:
                setattr(orchestrator, name, implementation)
            else:
                setattr(orchestrator, name, MethodType(implementation, orchestrator))
__all__ = ["bind_phase_methods"]
