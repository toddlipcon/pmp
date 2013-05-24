pmp
===

pmp is a poor man's profiler. It works by waking up once a millisecond and taking a stack trace of the target process.

Requirements
================
pmp must be built against libunwind.

Usage
=========

  pmp <pid> > /tmp/stacks.txt

This outputs a file with a stack trace per line, along with its associated count. To visualize this, it's best to use the FlameGraph project:

  cat /tmp/stacks.txt | c++filt | /path/to/FlameGraph.pl > /tmp/flamegraph.svg
  chrome /tmp/flamegraph.svg
