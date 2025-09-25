void func_0(void) {
  int iVar1;
  in_addr_t iVar2;
  int iVar3;
  size_t sVar4;
  ssize_t sVar5;
  char *pcVar6;
  sockaddr local_90;
  char local_7c [100];
  long local_18;
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c, 0, 100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  sVar4 = _strlen(local_7c);
  iVar1 = _socket(2, 1, 6);
  if (iVar1 != -1) {
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
    iVar2 = _inet_addr("127.0.0.1");
    local_90.sa_data._0_2_ = 0x8769;
    local_90.sa_data._2_4_ = iVar2;
    iVar3 = _connect(iVar1, &local_90, 0x10);
    if (iVar3 != -1) {
      sVar5 = _recv(iVar1, local_7c + sVar4, 99 - sVar4, 0);
      iVar3 = (int)sVar5;
      if ((iVar3 != -1) && (iVar3 != 0)) {
        local_7c[sVar4 + (ulong)(long)iVar3 / 1] = '\0';
        pcVar6 = _strchr(local_7c, 0xd);
        if (pcVar6 != (char *)0x0) {
          *pcVar6 = '\0';
        }
        pcVar6 = _strchr(local_7c, 10);
        if (pcVar6 != (char *)0x0) {
          *pcVar6 = '\0';
        }
      }
    }
  }
  if (iVar1 != -1) {
    _close(iVar1);
  }
  func_1(local_7c);
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
    ___stack_chk_fail();
  }
  return;
}