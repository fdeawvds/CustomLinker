#include <stdio.h>
#include <android/log.h>

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <math.h>
#include <sys/prctl.h>

#include <errno.h>

// void external_func();

void shared_function() {
  const char *msg = "This is a shared function from the shared library. MEOW TEST.";
  printf("\n\nShared function called.\n\n");
  size_t msg_len = strlen(msg);

  printf("Message length: %zu\n", msg_len);
  printf("\n%s\n\n", msg);

  // check if device supports MTE
  if (prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0) == 0) {
    printf("MTE is NOT supported on this device.\n");
  } else {
    /* INFO: won't even run. CSOLoader has no support for such devices. (arm9) */
    printf("MTE is supported on this device.\n");
  }

  // struct __android_log_message msgs = {
  //   .buffer_id = LOG_ID_DEFAULT,
  //   .message = "Hey!",
  //   .priority = ANDROID_LOG_INFO,
  //   .tag = "SharedLib",
  //   .struct_size = sizeof(struct __android_log_message)
  // };
  // __android_log_logd_logger(&msgs);

  __android_log_print(ANDROID_LOG_INFO, "SharedLib", "%s", msg);

  double value = 0.5;
  double result = cos(value);
  printf("Cosine of %.2f is %.2f\n", value, result);

  printf("\nShared function complete.\n\n");

  return;
}