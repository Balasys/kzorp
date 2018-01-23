These are the agreements (technical and otherwise) on the development of Kzorp:

The coordination of development is done on GitHub issue tracker.  Everyone is
welcome on board!

Every now code or bugfix should have the appropriate unit classes, and unit
classes for legacy code should be created.

Kzorp is technically independent entity from Zorp, i.e. not part of Zorp repository.

Versioning uses major.minor.patchlevel scheme as defined by http://semver.org/

Copyright is GPL v2+.

The source code is meant to be autotools compatible, and readily useable after 'make install'.
kzorp is meant to be packaged as the following (sets of) binary packages:
 - dkms module
 - python package, containing the python API and the kzorp binary 

In git, the 'stable' branch is meant to contain the stable code.

Kzorp's interfaces:

 - netlink socket (existing, to be documented, for non-python applications)
 - python API (TBD, for python applications)
 - end-user interface provided by the kzorp tool
 - iptables interface

The python API contains the classes (e.g. Zone, Dispatcher, Service) representing the world known by kzorp.
These classes have their methods to create the needed netlink messages.
They can be subclassed by Zorp or anyone wishing to build on kzorp.

The config file format for kzorp will be something almost, but not quite, entirely unlike policy.py for Zorp.


