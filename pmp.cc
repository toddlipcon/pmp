// Copyright (c) 2013, Todd Lipcon.

#include <sys/types.h>
#include <sys/user.h>
#include <iostream>
#include <unistd.h>
#include "process.h"

#include <stdlib.h>
#include "status.h"
#include "stringprintf.h"
#include <tr1/unordered_set>
#include <tr1/unordered_map>

namespace pmp {

using std::tr1::unordered_set;
using std::tr1::unordered_map;

bool should_shutdown = false;

class Summary {
public:
  void Add(const vector<StackFrame> &frames) {
    string s;
    s.reserve(32000);

    for (int i = frames.size() - 1; i >= 0; i--) {
      const StackFrame &f = frames[i];
      if (i != frames.size() - 1) {
        s.append("; ");
      }
      s.append(f.proc_name);
    }

    unordered_map<string, int>::iterator it = trace_counts_.find(s);
    if (it != trace_counts_.end()) {
      (*it).second++;
    } else {
      trace_counts_[s] = 1;
    }
  }

  void Dump() {
    for (unordered_map<string, int>::iterator it = trace_counts_.begin();
         it != trace_counts_.end();
         ++it) {
      std::cout << (*it).first << "\t" << (*it).second << std::endl;
    }
  }

private:
  unordered_map<string, int> trace_counts_;
};

Status TakeSample(pid_t pid, Summary *summary) {
  bool print_traces = false;
  TracedProcess proc(pid);
  unordered_set<pid_t> attached_tids;

  RETURN_NOT_OK(proc.Attach());
  attached_tids.insert(pid);

  vector<pid_t> tids;
  RETURN_NOT_OK(proc.ListThreads(&tids));

  for (uint i = 0; i < tids.size(); i++) {
    pid_t tid = tids[i];

    if (!attached_tids.count(tid)) {
      RETURN_NOT_OK(proc.AttachThread(tid));
      attached_tids.insert(tid);
    }

    vector<StackFrame> frames;
    Status stat = proc.DoBacktrace(tid, &frames);
    if (!stat.ok()) {
      std::cerr << "couldnt backtrace pid " << tid << ": " << stat.ToString();
      continue;
    }

    if (print_traces) {
      std::cout << "Thread " << tid << ":" << std::endl;
      for (uint i = 0; i < frames.size(); i++) {
        StackFrame &f = frames[i];
        std::cout << "\t#" << i << "\t" << std::hex << f.ip << std::dec
                  << "\t" << f.proc_name << std::endl;
      }
    }
    summary->Add(frames);
  }
  return Status::OK();
}

Status DoPmp(pid_t pid) {
  Summary summary;
  int samples = 0;

  while (!should_shutdown) {
    usleep(1000);
    Status s = TakeSample(pid, &summary);
    if (!s.ok()) {
      if (samples == 0) {
        return s;
      } else {
        break;
      }
    }
    samples++;
  }

  summary.Dump();

  return Status::OK();
}

void HandleSigInt(int signal) {
  should_shutdown = true;
}

void InstallSignalHandler() {
  signal(SIGINT, HandleSigInt);
}

}

using namespace pmp;

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " pid" << std::endl;
    exit(1);
  }

  int pid = atoi(argv[1]);
  if (pid <= 0) {
    std::cerr << "bad pid: " << argv[1] << std::endl;
    exit(2);
  }

  InstallSignalHandler();

  Status s = DoPmp(pid);
  if (!s.ok()) {
    std::cerr << "failed: " << s.ToString();
    return 1;
  }

  return 0;
}
