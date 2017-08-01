init:
	pip install -r requirements.txt
	pip install -r requirements.test.txt

install:
	python setup.py install

lint:
	pep8 **/*.py
	pyflakes zuul_alpha/

test:
	nosetests
