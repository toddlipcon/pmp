#ifndef PMP_PROCESS_H
#define PMP_PROCESS_H

#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>

#include "status.h"
#include "stringprintf.h"

#include <libunwind.h>
#include <libunwind-ptrace.h>
#include <tr1/unordered_set>

namespace pmp {

using std::tr1::unordered_set;

struct StackFrame {
  std::string proc_name;
  unw_word_t proc_off;
  unw_word_t ip;
};

class UnwindAddrSpace {
public:
  UnwindAddrSpace() :
    initted_(false),
    as_(0),
    upt_info_(NULL)
  {}

  ~UnwindAddrSpace() {
    if (upt_info_ != NULL) {
      _UPT_destroy(upt_info_);
    }
  }

  Status Init(pid_t target_pid) {
    if (initted_) return Status::OK();

    as_ = unw_create_addr_space(&_UPT_accessors, 0);
    if (!as_) {
      return Status::IOError("Unable to init addr space");
    }

    upt_info_ = _UPT_create(target_pid);
    if (!upt_info_) {
      return Status::IOError("Unable to init UPT_info");
    }

    initted_ = true;
    return Status::OK();
  }

  Status DoBacktrace(std::vector<StackFrame> *frames) {
    if (!initted_) {
      return Status::IOError("not initted");
    }
    unw_cursor_t cursor;
    int ret = unw_init_remote(&cursor, as_, upt_info_);
    if (ret != 0) {
      return Status::IOError(
        StringPrintf("Unable to init unw_remote: rc=%d", ret));
    }

    bool print_names = true;
    char buf[1024];
    unw_word_t ip, sp, start_ip = 0, off;
    int n = 0;
    while (true) {
      if ((ret = unw_get_reg (&cursor, UNW_REG_IP, &ip)) < 0
          || (ret = unw_get_reg (&cursor, UNW_REG_SP, &sp)) < 0) {
        return Status::IOError(
          StringPrintf("unw_get_reg/unw_get_proc_name() failed: ret=%d\n", ret));
      }

      if (n == 0)
        start_ip = ip;

      StackFrame f;

      f.ip = ip;

      if (print_names) {
        buf[0] = '\0';
        unw_get_proc_name (&cursor, buf, sizeof (buf), &off);
        f.proc_name = std::string(buf);
        f.proc_off = off;
      } else {
        f.proc_off = 0;
      }

      frames->push_back(f);

      // Traverse up
      if ((ret = unw_step(&cursor)) < 0) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        return Status::IOError(
          StringPrintf("FAILURE: unw_step() returned %d for ip=%lx (start ip=%lx)\n",
                       ret, (long) ip, (long) start_ip));
      }
      if (ret == 0) {
        // Last frame
        break;
      }

      if (++n > 64)
      {
        /* guard against bad unwind info in old libraries... */
        return Status::IOError(
          StringPrintf("too deeply nested---assuming bogus unwind (start ip=%lx)\n",
                       (long) start_ip));
        break;
      }
    }

    return Status::OK();
  }

  unw_addr_space_t as();

private:
  bool initted_;

  unw_addr_space_t as_;
  void *upt_info_;
};

class TracedProcess {
public:
  TracedProcess(pid_t pid) :
    pid_(pid)
  {}

  ~TracedProcess() {
    Detach();
  }

  Status Attach() {
    return AttachThread(pid_);
  }

  Status AttachThread(pid_t tid) {
    // Attach with ptrace.
    {
      if (ptrace(PTRACE_ATTACH, tid, 0, 0) != 0) {
        return Status::IOError(StringPrintf("Couldn't attach to thread %d", tid),
                               strerror(errno));
      }

      if (1 || tid == pid_) {
        int stat;
        pid_t res = waitpid(tid, &stat, WUNTRACED | __WALL);
        if ((res != tid)) {
          return Status::IOError(
            StringPrintf("waitpid result %d didn't match pid %d",
                         res, pid_));
        }

        if (!(WIFSTOPPED(stat))) {
          return Status::IOError(
            StringPrintf("Unexpected wait result: %d", stat));
        }
      }
    }

    attached_.insert(tid);

    return Status::OK();
  }

  Status DoBacktrace(pid_t target_pid, vector<StackFrame> *frames) {
    UnwindAddrSpace as;
    RETURN_NOT_OK(as.Init(target_pid));
    RETURN_NOT_OK(as.DoBacktrace(frames));
    return Status::OK();
  }


  Status Detach() {
    for (unordered_set<pid_t>::const_iterator it = attached_.begin();
         it != attached_.end();
         ++it) {
      pid_t tid = *it;
      if (ptrace(PTRACE_DETACH, tid, 0, 0) != 0) {
        return Status::IOError("Couldn't detach", strerror(errno));
      }
      attached_.erase(it);
    }
    return Status::OK();
  }

  Status ListThreads(vector<pid_t> *tids) {
    string task_dir = StringPrintf("/proc/%d/task/", pid_);
    DIR *dir = opendir(task_dir.c_str());
    if (dir == NULL) {
      return Status::IOError("failed to open task dir", strerror(errno));
    }
    struct dirent *d;
    while ((d = readdir(dir)) != NULL) {
      if (d->d_name[0] != '.') {
        int tid = atoi(d->d_name);
        if (tid == 0) {
          std::cerr << "bad tid in " << task_dir << ": " << d->d_name << std::endl;
          continue;
        }
        tids->push_back(tid);
      }
    }
    closedir(dir);
    return Status::OK();
  }

  pid_t pid() const { return pid_; }


private:
  pid_t pid_;
  unordered_set<pid_t> attached_;
};

} // namespace pmp

#endif
