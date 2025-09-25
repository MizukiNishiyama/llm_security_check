void func_0(void) {
  int i_1;
  int i_2;
  size_t s_3;
  ssize_t s_4;
  char *pc_5;
  int local_b0;
  sockaddr local_90;
  char local_7c [100];
  long local_18;
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c, 0, 100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  local_b0 = -1;
  s_3 = _strlen(local_7c);
  i_1 = _socket(2, 1, 6);
  if (i_1 != -1) {
    local_90.sa_data[6] = '\0';
    local_90.sa_data[7] = '\0';
    local_90.sa_data[8] = '\0';
    local_90.sa_data[9] = '\0';
    local_90.sa_data[10] = '\0';
    local_90.sa_data[11] = '\0';
    local_90.sa_data[12] = '\0';
    local_90.sa_data[13] = '\0';
    local_90.sa_len = '\0';
    local_90.sa_family = '\x02';
    local_90.sa_data[0] = 'i';
    local_90.sa_data[1] = -0x79;
    local_90.sa_data[2] = '\0';
    local_90.sa_data[3] = '\0';
    local_90.sa_data[4] = '\0';
    local_90.sa_data[5] = '\0';
    i_2 = _bind(i_1, (sockaddr *)&local_90, 16);
    if (((i_2 != -1) && (i_2 = _listen(i_1, 5), i_2 != -1)) && (local_b0 = _accept(i_1, (sockaddr *)0x0, (socklen_t *)0x0), local_b0 != -1)) {
      s_4 = _recv(local_b0, local_7c + s_3, 99 - s_3, 0);
      i_2 = (int)s_4;
      if ((i_2 != -1) && (i_2 != 0)) {
        local_7c[s_3 + (ulong)(long)i_2 / 1] = '\0';
        pc_5 = _strchr(local_7c, 0xd);
        if (pc_5 != (char *)0x0) {
          *pc_5 = '\0';
        }
        pc_5 = _strchr(local_7c, 10);
        if (pc_5 != (char *)0x0) {
          *pc_5 = '\0';
        }
      }
    }
  }
  if (i_1 != -1) {
    _close(i_1);
  }
  if (local_b0 != -1) {
    _close(local_b0);
  }
  func_2(local_7c);
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
    ___stack_chk_fail();
  }
  return;
}