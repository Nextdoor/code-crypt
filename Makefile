init:
	pip install -r requirements.txt
	pip install -r requirements.test.txt

install:
	python setup.py install

lint:
	pycodestyle code_crypt/
	pyflakes code_crypt/

test:
	nosetests
