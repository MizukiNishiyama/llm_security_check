void func_0(void) {
  int i_1;
  int i_2;
  int i_3;
  size_t s_4;
  ssize_t s_5;
  char *pc_6;
  sockaddr local_90;
  char local_7c [100];
  long l_8;
  l_8 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c, 0, 100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  s_4 = _strlen(local_7c);
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
    local_90.sa_data[0] = '\0';
    local_90.sa_data[1] = '\0';
    local_90.sa_data[2] = '\0';
    local_90.sa_data[3] = '\0';
    local_90.sa_data[4] = '\0';
    local_90.sa_data[5] = '\0';
    i_2 = _inet_addr("127.0.0.1");
    local_90.sa_data._0_2_ = 0x8769;
    local_90.sa_data._2_4_ = i_2;
    i_3 = _connect(i_1, &local_90, 0x10);
    if (i_3 != -1) {
      s_5 = _recv(i_1, local_7c + s_4, 99 - s_4, 0);
      i_3 = (int)s_5;
      if ((i_3 != -1) && (i_3 != 0)) {
        local_7c[s_4 + (ulong)(long)i_3 / 1] = '\0';
        pc_6 = _strchr(local_7c, 0xd);
        if (pc_6 != (char *)0x0) {
          *pc_6 = '\0';
        }
        pc_6 = _strchr(local_7c, 10);
        if (pc_6 != (char *)0x0) {
          *pc_6 = '\0';
        }
      }
    }
  }
  if (i_1 != -1) {
    _close(i_1);
  }
  func_2(local_7c);
  if (*(long *)PTR____stack_chk_guard_100004000 != l_8) {
    ___stack_chk_fail();
  }
  return;
}