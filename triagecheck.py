from volatility.framework import interfaces
import datetime
import logging
import ntpath


vollog = loging.getLogger(__name__)


class TriageCheck(interfaces.plugins.PluginInterface):
    """Carries out some basic 'malware101' checks to triage an image."""
    _required_framework_version =(1,0,0)

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols",
                                                description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist',
                                           plugin = pslist.PsList,
                                           version = (1, 0, 0)),
            requirements.VersionRequirement(name = 'info', component = info.Info, version = (1, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True)]
