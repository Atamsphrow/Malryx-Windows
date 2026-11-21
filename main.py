"""Point d'entrée de Malryx.

  Malryx.exe                  ouvre l'application
  Malryx.exe --minimized      démarre dans la zone de notification (démarrage de Windows)
  Malryx.exe --scan <chemin>  analyse un fichier / dossier (menu contextuel de l'Explorateur)
"""
import argparse
import os
import sys


def main():
    p = argparse.ArgumentParser(prog="Malryx")
    p.add_argument("--minimized", action="store_true")
    p.add_argument("--scan", nargs="*", default=None)
    args, _ = p.parse_known_args()

    if sys.platform == "win32":
        import ctypes
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Malryx.AntiMalware")
        except Exception:
            pass
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")

    from PySide6.QtWidgets import QApplication
    app = QApplication(sys.argv)
    app.setApplicationName("Malryx")
    app.setQuitOnLastWindowClosed(False)

    from malryx.gui.main_window import MainWindow, send_to_running
    from malryx.gui.theme import QSS
    if send_to_running(args):
        return 0
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    w = MainWindow(start_minimized=args.minimized, scan_paths=args.scan)
    app.aboutToQuit.connect(w.cleanup)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
