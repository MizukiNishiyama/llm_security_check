void CWE78_OS_Command_Injection__char_listen_socket_execl_81::func_0(void) {
  int iVar1;
  ssize_t sVar2;
  undefined8 *local_c8;
  undefined8 **local_c0;
  size_t local_b8;
  int local_b0;
  int local_ac;
  undefined1 *local_a8;
  int local_9c;
  char *local_98;
  sockaddr local_90;
  char local_7c [100];
  long local_18;
  {
    local_18 = *(long *)PTR____stack_chk_guard_100004008;
    _memset(local_7c,0,100);
    local_7c[0] = 'l';
    local_7c[1] = 0x73;
    local_7c[2] = 0x20;
    local_ac = 0xffffffff;
    local_b0 = -1;
    local_98 = local_7c;
    local_b8 = _strlen(local_7c);
    local_ac = _socket(2,1,6);
    if (local_ac != -1) {
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
      iVar1 = _bind(local_ac,&local_90,0x10);
      if (((iVar1 != -1) && (iVar1 = _listen(local_ac,5), iVar1 != -1)) && (local_b0 = _accept(local_ac,(sockaddr *)0x0,(socklen_t *)0x0), local_b0 != -1)) {
        sVar2 = _recv(local_b0,local_98 + local_b8,99 - local_b8,0);
        local_9c = (int)sVar2;
        if ((local_9c != -1) && (local_9c != 0)) {
          local_98[local_b8 + (ulong)(long)local_9c / 1] = '\0';
          local_a8 = (undefined1 *)func_2(local_98,0xd);
          if (local_a8 != (undefined1 *)0x0) {
            *local_a8 = 0;
          }
          local_a8 = (undefined1 *)func_2(local_98,10);
          if (local_a8 != (undefined1 *)0x0) {
            *local_a8 = 0;
          }
        }
      }
    }
    if (local_ac != -1) {
      _close(local_ac);
    }
    if (local_b0 != -1) {
      _close(local_b0);
    }
    local_c8 = (undefined8 *)0x0;
    func_3();
    local_c0 = &local_c8;
    (*(code *)*local_c8)(&local_c8,local_98);
    if (*(long *)PTR____stack_chk_guard_100004008 != local_18) {
                    
      ___stack_chk_fail();
    }
    return;
  }
}