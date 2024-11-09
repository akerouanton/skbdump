# skbdump

This project aims at providing an easy way to capture traffic generated or destined to containers. Unlike tcpdump, it
doesn't need to be run in a specific netns (ie. it's netns agnostic), or to be attached to a specific interface.

Instead, it's attached to a cgroup hierarchy, and thus will see traffic generated or received by any software running
under that hierarchy. Currently, it also captures kernel-generated, but doesn't support kernel-destined, and rejected
packets yet.

Note that this project is under active development.
