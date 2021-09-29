#!/usr/bin/env python3

import sys
import signal

from MainWindow import MainWindow

from PySide2.QtCore import Qt, QObject

from PySide2.QtWidgets import QApplication



if(__name__ == '__main__'):

	# Setup Qt application
	app = QApplication(sys.argv)
	signal.signal(signal.SIGINT, signal.SIG_DFL)

	main_window = MainWindow()
	main_window.show()

	sys.exit(app.exec_())
