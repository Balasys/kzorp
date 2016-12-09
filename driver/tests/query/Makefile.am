check_SCRIPTS = \
	KZorpTestCaseQueryNDim.py \
	KZorpTestCaseQueryZones.py

AM_TESTS_ENVIRONMENT = export PYTHONPATH=$(top_srcdir)/driver/tests/base:$(top_srcdir)/pylib;

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)
AM_PY_LOG_FLAGS = -B

TESTS = $(check_SCRIPTS)
EXTRA_DIST = $(check_SCRIPTS) KZorpBaseTestCaseQuery.py
