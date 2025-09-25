void func_0(void) {
  uint local_b0;
  sockaddr local_90;
  char local_7c [100];
  long local_18;
  uint uVar1;
  uint uVar2;
  size_t sVar3;
  char *pcVar4;
  int iVar5;
  local_18 = *(long *)PTR____stack_chk_guard_100004000;
  _memset(local_7c, 0, 100);
  local_7c[0] = 'l';
  local_7c[1] = 0x73;
  local_7c[2] = 0x20;
  local_b0 = 0xffffffff;
  sVar3 = _strlen(local_7c);
  uVar1 = _socket(2, 1, 6);
  pcVar4 = (char *)(ulong)uVar1;
  if (uVar1 != 0xffffffff) {
    local_90.sa_data[6] = '\0';
    local_90.sa_data[7] = '\0';
    local_90.sa_data[8] = '\0';
    local_90.sa_data[9] = '\0';
    local_90.sa_data[10] = '\0';
    local_90.sa_data[0xb] = '\0';
    local_90.sa_data[0xc] = '\0';
    local_90.sa_data[0xd] = '\0';
    local_90.sa_len = '\0';
    local_90.sa_family = '\x02';
    local_90.sa_data[0] = 'i';
    local_90.sa_data[1] = -0x79;
    local_90.sa_data[2] = '\0';
    local_90.sa_data[3] = '\0';
    local_90.sa_data[4] = '\0';
    local_90.sa_data[5] = '\0';
    uVar2 = _bind(uVar1, &local_90, 0x10);
    pcVar4 = (char *)(ulong)uVar2;
    if (uVar2 != 0xffffffff) {
      uVar2 = _listen(uVar1, 5);
      pcVar4 = (char *)(ulong)uVar2;
      if (uVar2 != 0xffffffff) {
        local_b0 = _accept(uVar1, (sockaddr *)0x0, (socklen_t *)0x0);
        pcVar4 = (char *)(ulong)local_b0;
        if (local_b0 != 0xffffffff) {
          pcVar4 = (char *)_recv(local_b0, local_7c + sVar3, 99 - sVar3, 0);
          iVar5 = (int)pcVar4;
          if ((iVar5 != -1) && (iVar5 != 0)) {
            local_7c[sVar3 + (ulong)(long)iVar5 / 1] = '\0';
            pcVar4 = _strchr(local_7c, 0xd);
            if (pcVar4 != (char *)0x0) {
              *pcVar4 = '\0';
            }
            pcVar4 = _strchr(local_7c, 10);
            if (pcVar4 != (char *)0x0) {
              *pcVar4 = '\0';
            }
          }
        }
      }
    }
  }
  if (uVar1 != 0xffffffff) {
    uVar1 = _close(uVar1);
    pcVar4 = (char *)(ulong)uVar1;
  }
  if (local_b0 != 0xffffffff) {
    uVar1 = _close(local_b0);
    pcVar4 = (char *)(ulong)uVar1;
  }
  _CWE78_OS_Command_Injection__char_listen_socket_execl_68_badData = local_7c;
  func_2(pcVar4);
  if (*(long *)PTR____stack_chk_guard_100004000 != local_18) {
    ___stack_chk_fail();
  }
  return;
}