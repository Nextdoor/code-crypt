init:
	pip install -r requirements.txt
	pip install -r requirements.test.txt

install:
	python setup.py install

lint:
	pep8 **/*.py
	pyflakes code_crypt/

test:
	nosetests
