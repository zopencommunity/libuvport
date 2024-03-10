diff --git a/src/unix/os390.c b/src/unix/os390.c
index 1b277292..e3c2252b 100644
--- a/src/unix/os390.c
+++ b/src/unix/os390.c
@@ -602,6 +602,9 @@ void uv__platform_invalidate_fd(uv_loop_t* loop, int fd) {
         events[i].fd = -1;
 
   /* Remove the file descriptor from the epoll. */
+  dummy.events = 0;
+  dummy.fd = fd;
+  dummy.is_msg = 0;
   if (loop->ep != NULL)
     epoll_ctl(loop->ep, EPOLL_CTL_DEL, fd, &dummy);
 }
@@ -701,12 +704,8 @@ int uv__fs_event_stop(uv_fs_event_t* handle) {
   memcpy(reg_struct.__rfis_rftok, handle->rfis_rftok,
          sizeof(handle->rfis_rftok));
 
-  /*
-   * This call will take "/" as the path argument in case we
-   * don't care to supply the correct path. The system will simply
-   * ignore it.
-   */
-  rc = __w_pioctl("/", _IOCC_REGFILEINT, sizeof(reg_struct), &reg_struct);
+  rc = __w_pioctl(handle->path == NULL ? "/" : handle->path,
+                  _IOCC_REGFILEINT, sizeof(reg_struct), &reg_struct);
   if (rc != 0 && errno != EALREADY && errno != ENOENT)
     abort();
 
@@ -755,26 +754,47 @@ static int os390_message_queue_handler(uv__os390_epoll* ep) {
 
   msglen = msgrcv(ep->msg_queue, &msg, sizeof(msg), 0, IPC_NOWAIT);
 
-  if (msglen == -1 && errno == ENOMSG)
-    return 0;
-
   if (msglen == -1)
-    abort();
+    if (errno == ENOMSG)
+      return 0;
+    else if (errno == EINVAL)
+      return -1;
+    else
+      abort();
 
   events = 0;
   if (msg.__rfim_event == _RFIM_ATTR || msg.__rfim_event == _RFIM_WRITE)
     events = UV_CHANGE;
   else if (msg.__rfim_event == _RFIM_RENAME || msg.__rfim_event == _RFIM_UNLINK)
     events = UV_RENAME;
-  else if (msg.__rfim_event == 156)
-    /* TODO(gabylb): zos - this event should not happen, need to investigate.
+  else if (msg.__rfim_event == 156) {
+    /* TODO(gabylb): zos - investigate why this event is occuring as it should
+     * not happen based on https://github.ibm.com/open-z/node-build/issues/199.
      *
-     * This event seems to occur when the watched file is [re]moved, or an
-     * editor (like vim) renames then creates the file on save (for vim, that's
-     * when backupcopy=no|auto).
+     * This (undocumented?) event seems to occur when the watched file
+     * is [re]moved, or an editor (like vim) renames then creates the file
+     * on save (for vim, that's when backupcopy=no|auto), which causes
+     * __w_pioctl to fail as the file wasn't yet created; the sleep is
+     * to help resolve the rename-create issue.
+     *
+     * This is a temporary workaround because on extremely busy systems,
+     * timeouts cannot guarantee deterministic behaviour. Since the inode
+     * number changes, they are technically NOT the same file. Thus this kind
+     * of monitoring is not really valid. If there is a real issue, the
+     * application itself should be adjusted to deal with time gap. The current
+     * monitoring method has a gap, when inotify becomes availlable, we should
+     * switch to it.
+     *
+     * See: https://github.ibm.com/open-z/node-build/issues/656
+     * 
+     * TODO: zos - resolve this issue on z/OS for V2R4 if possible, and
+     * remove entirely when V2R5 is the min supported level and only inotify
+     * is used. This should not be upstreamed.
      */
+    struct timespec timeout = { 0, 1000000 }; /* 1ms. */
     events = UV_RENAME;
-  else
+    nanosleep(&timeout, NULL);
+  } else
     /* Some event that we are not interested in. */
     return 0;
 
@@ -852,6 +872,7 @@ void uv__io_poll(uv_loop_t* loop, int timeout) {
 
     e.events = w->pevents;
     e.fd = w->fd;
+    e.is_msg = 0;
 
     if (w->events == 0)
       op = EPOLL_CTL_ADD;
@@ -901,12 +922,6 @@ void uv__io_poll(uv_loop_t* loop, int timeout) {
     if (sizeof(int32_t) == sizeof(long) && timeout >= max_safe_timeout)
       timeout = max_safe_timeout;
 
-    /* Store the current timeout in a location that's globally accessible so
-     * other locations like uv__work_done() can determine whether the queue
-     * of events in the callback were waiting when poll was called.
-     */
-    lfields->current_timeout = timeout;
-
     nfds = epoll_wait(loop->ep, events,
                       ARRAY_SIZE(events), timeout);
 
@@ -970,7 +985,13 @@ void uv__io_poll(uv_loop_t* loop, int timeout) {
 
       ep = loop->ep;
       if (pe->is_msg) {
-        os390_message_queue_handler(ep);
+        if (os390_message_queue_handler(ep) == -1) {
+          /* The user has deleted the System V message queue. Highly likely
+           * that the process is being shut down. So stop listening to it.
+           */
+          epoll_ctl(loop->ep, EPOLL_CTL_DEL, ep->msg_queue, pe);
+          loop->backend_fd = -1;
+        }
         nevents++;
         continue;
       }
@@ -1014,11 +1035,9 @@ void uv__io_poll(uv_loop_t* loop, int timeout) {
       }
     }
 
-    uv__metrics_inc_events(loop, nevents);
     if (reset_timeout != 0) {
       timeout = user_timeout;
       reset_timeout = 0;
-      uv__metrics_inc_events_waiting(loop, nevents);
     }
 
     if (have_signals != 0) {
