init:
	pip install -r requirements.txt
	pip install -r requirements.test.txt
	python setup.py install

lint:
	$(info Linting...)
	pep8 **/*.py
	pyflakes zuul_alpha/

test:
	nosetests -s
