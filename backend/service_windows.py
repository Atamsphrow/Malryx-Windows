"""Service Windows Malryx (W2) — heberge le backend en service SCM.

Le service lance :
- l'API FastAPI (uvicorn) sur 127.0.0.1 (port des reglages), utilisee
  par l'interface Flutter ;
- la protection temps reel (ReadDirectoryChangesW) si elle est active
  dans les reglages.

Dependance : pywin32 (Windows uniquement). Installation / controle :
    python service_windows.py install
    python service_windows.py start
    python service_windows.py stop
    python service_windows.py remove

Limite v1 assumee : un service en session 0 n'affiche pas de toast sur
le bureau (voir core/notify.py) ; les alertes passent par l'UI et le
journal. L'installateur W6 enregistrera ce service proprement.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    HAS_PYWIN32 = True
except ImportError:  # hors Windows ou pywin32 absent : module importable quand meme
    HAS_PYWIN32 = False


if HAS_PYWIN32:

    class MalryxService(win32serviceutil.ServiceFramework):
        _svc_name_ = "Malryx"
        _svc_display_name_ = "Malryx Antivirus"
        _svc_description_ = (
            "Backend Malryx : analyse antivirus (ClamAV, YARA, heuristiques) "
            "et protection en temps reel."
        )

        def __init__(self, args):
            super().__init__(args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._server = None
            self._state = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                self._run()
            except Exception as exc:  # journalise dans l'observateur d'evenements
                servicemanager.LogErrorMsg(f"Malryx : erreur fatale : {exc!r}")
                raise

        def _run(self):
            import uvicorn

            from core.app_state import init_state
            from core.config import DEFAULT_PORT
            from main import app

            self._state = init_state()
            if self._state.settings.realtime_protection:
                # Le watcher vit dans une boucle asyncio dediee (thread).
                import asyncio

                def run_watcher():
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                    async def boot():
                        self._state.realtime.start()

                    loop.run_until_complete(boot())
                    loop.run_forever()

                threading.Thread(
                    target=run_watcher, daemon=True, name="malryx-realtime"
                ).start()

            config = uvicorn.Config(
                app,
                host="127.0.0.1",
                port=DEFAULT_PORT,
                log_level="warning",
            )
            self._server = uvicorn.Server(config)
            thread = threading.Thread(
                target=self._server.run, daemon=True, name="malryx-api"
            )
            thread.start()

            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
            if self._server is not None:
                self._server.should_exit = True
            if self._state is not None:
                self._state.shutdown()


if __name__ == "__main__":
    if not HAS_PYWIN32:
        print(
            "pywin32 introuvable : ce module ne sert que sous Windows "
            "avec pywin32 installe (pip install pywin32)."
        )
        raise SystemExit(2)
    win32serviceutil.HandleCommandLine(MalryxService)
