void func_0(void) {
  int i_r1;
  int i_r2;
  int i_r3;
  size_t s_r4;
  ssize_t s_r5;
  char *pcVar6;
  char *local_98;
  sockaddr local_90;
  char local_7c [100];
  long local_18;
  i_r2 = 0;
  i_r3 = 0;
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c, 0, 100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  local_98 = local_7c;
  s_r4 = _strlen(local_7c);
  i_r1 = _socket(2, 1, 6);
  if (i_r1 != -1) {
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
    i_r2 = _inet_addr("127.0.0.1");
    local_90.sa_data._0_2_ = 0x8769;
    local_90.sa_data._2_4_ = i_r2;
    i_r3 = _connect(i_r1, &local_90, 0x10);
    if (i_r3 != -1) {
      s_r5 = _recv(i_r1, local_98 + s_r4, 99 - s_r4, 0);
      i_r3 = (int)s_r5;
      if ((i_r3 != -1) && (i_r3 != 0)) {
        local_98[s_r4 + (ulong)(long)i_r3 / 1] = '\0';
        pcVar6 = _strchr(local_98, 0xd);
        if (pcVar6 != (char *)0x0) {
          *pcVar6 = '\0';
        }
        pcVar6 = _strchr(local_98, 10);
        if (pcVar6 != (char *)0x0) {
          *pcVar6 = '\0';
        }
      }
    }
  }
  if (i_r1 != -1) {
    _close(i_r1);
  }
  func_2(&local_98);
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
    ___stack_chk_fail();
  }
  return;
}