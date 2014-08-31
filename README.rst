=======================
Docker Isolation Tester
=======================

WARNING: Do not run this, it may break your system!

This script tries to test the container limits:

* try to allocate as much memory as we can get
* try to fork processes
* try to connect to the outside world

.. code:: bash

    docker build -t dit .
    docker run --memory=30M -u nobody -t dit
