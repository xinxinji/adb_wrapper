# -*- coding: utf-8 -*-
import os
import posixpath
from datetime import datetime
import re

from .adb_wrapper import AdbWrapper
from .adb_wrapper import ADB_SERVER_PORT
from .adb_wrapper import FILE_TRANSFORM_TIMEOUT
from .adb_wrapper import BUGREPORT_TIMEOUT
from .adb_wrapper import NOFILEORFOLDER, PERMISSION_DENY, READONLY, SHELL_FAILED
from .adb_wrapper import AdbFailException, AdbConnectFail
from .intent import Intent

class AdbAuto(AdbWrapper):
    '''Here is a little smart AdbWrapper'''
    file_property_nose_re = re.compile((r'(?P<permission>[-lspbcdrwx\.]{10}) *'
                                        r'(?P<linknum>\d+) *'
                                        r'(?P<group>\S*) *(?P<owner>\S*) *'
                                        r'(?P<filesize>\d{0,10}) *'
                                        r'(?P<datetime>\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}) *'
                                        r'(?P<filename>.*)'))
    file_property_se_re = re.compile((r'(?P<permission>[-lspbcdrwx\.]{10}) *'
                                      r'(?P<linknum>\d+) *'
                                      r'(?P<group>\S*) *(?P<owner>\S*) *'
                                      r'(?P<seprop>\S*) *'
                                      r'(?P<filesize>\d{0,10}) *'
                                      r'(?P<datetime>\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}) *'
                                      r'(?P<filename>.*)'))
    netcfg_re = re.compile((r'(?P<interfacename>[\w\-]+) *'
                            r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d* *'
                            r'0x\d* '
                            r'(?P<mac>([0-9a-fA-F]{2}[:]){5}[0-9a-fA-F]{2})'))
    ifconfig_re = re.compile((r'(?P<interfacename>[\w\-]+)\s*Link encap:(?P<linkencap>\w+)\s*'
                              r'(?:Loopback|\s*?HWaddr (?P<mac>[0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}))\s*'
                              r'(?:Driver (?P<driver>\w+)\s*)?'
                              r'(?:inet addr:(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*)?'
                              r'(?:Bcast:(?P<bcast>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*)?'
                              r'(?:Mask:(?P<mask>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) *)?'))

    mac_re = re.compile(r'[0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}[:][0-9a-fA-F]{2}')
    # Android L ps command:user  pid   ppid   vsize  rss    wchan  pc     state codes      name
    android_ps_re = re.compile(r'(\w+) +(\d+) *(\d+) +(\d+) +(\d+) *(.*?) +(\w*) +(D|R|S|T|W|X|Z) +(.*)')
    # BusyBox ps command:pid    userid time      command
    busybox_ps_re = re.compile(r'(\d+) +(\d+) +(\d+:\d+) +(.*)')
    # mount command:
    mount_re = re.compile(r'(?P<device>.*?) on (?P<mount_point>/.*?) type (?P<type>.*?) \((?P<options>.*?)\)')
    pm_failure_re = re.compile(r'Failure \[(.*?)\]')
    pm_setting_re = re.compile(r'(Package|Component) [\w\.]*? new state: (disabled|enabled)')
    error_re = re.compile(r'Error: (.*)')
    warn_re = re.compile(r'Warning: (.*)')

    def __init__(self, adb_file=None, logger=None, adb_server_port=ADB_SERVER_PORT):
        super(AdbAuto, self).__init__(adb_file, logger)

    def check_connection(self, device=None):
        '''
        Use adb shell exit to check real connection status
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: Result [Connection True(True)/Other Status(False)](bool)
        '''
        self.logger.info("check_connection: start")
        try:
            stdout, stderr = self.shell(cmd="exit", device=device, timeout=5)
        except AdbFailException as err:
            res = False
            self.logger.error("adb connect error: %s", err.msg)
        else:
            if stdout != u"" or stderr != u"":
                res = False
                self.logger.info("adb connection: False")
            else:
                res = True
                self.logger.info("adb connection: True")
            self.logger.info("check_connection: success")
        return res

    def connect_auto(self, device=None, retry_times=3):
        '''
        Before connect, auto check exist connect from adb devices
        If already in connect
            *. If in connect with wrong status, do disconnect
            *. check connect status.
                1. return True if connect
        do connect
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               retry_times (int)
        Output: Device [SN or IP:Port](str)
        '''
        self.logger.info("connect_auto: start")
        if device:
            _device = device
        else:
            if self._device:
                _device = self._device
            else:
                self.logger.error("connect_auto: device not define")
                raise AdbFailException("device not define")
        try:
            # Check Devices List First
            devices = self.devices()
            for exist_device in devices:
                if _device in exist_device:
                    device_name = exist_device  # Because Input Device may be IP only, translate it to SN
                    self.logger.info("connect_auto: Device in adb devices - %s", device_name)
                    if devices[device_name] != u'device':
                        self.logger.error("connect_auto: Device status - %s", devices[device_name])
                        self.logger.error("connect_auto: Try to disconnect it")
                        self.disconnect(device_name)
                    else:
                        if self.check_connection(device=device_name):
                            self.logger.info("connect_auto: already connected")
                            return device_name
                    break
            else:
                self.logger.error("connect_auto: No device in adb devices")
        except AdbFailException:
            pass
        # Device not in Devices List or Connection status False, try do adb connect
        for num in range(retry_times):
            try:
                device_name = self.connect(_device)
                self.logger.info("connect_auto: connect success")
                if self.check_connection(device=device_name):
                    self.logger.info("connect_auto: check connect Pass")
                    return device_name
                else:
                    self.logger.error("connect_auto: check connect Fail")
                continue
            except (AdbFailException, AdbConnectFail):
                if num == retry_times - 1:
                    self.logger.error("connect_auto: connect keep fail in %s times", retry_times)
                    raise
        self.logger.error("connect_auto: connect success but always check connection fail")
        raise AdbConnectFail

    def disconnect_auto(self, device=None):
        '''
        Nothing can be do for more auto, just do disconnect directly
        Add this function here just for more orderly
        '''
        return self.disconnect(device=device)

    def shell_auto(self, cmd, device=None, timeout=None):
        '''
        Do adb connect auto then do shell cmd
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               cmd [list or string]
               timeout [int/float/None(infinite)]
        Output: stdout[from adb command](str)
                stderr(str)
        '''
        self.logger.info("shell_auto: start")
        try:
            devicename = self.connect_auto(device=device)
            stdout, stderr = self.shell(cmd=cmd, device=devicename, timeout=timeout)
            self.logger.info("shell_auto: complete")
        except (AdbFailException, AdbConnectFail):
            raise
        return stdout, stderr

    def is_root(self, device=None):
        '''
        Use adb shell id to get adb connect permission
        Do connect_auto first, then shell id
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: Result(bool)
        '''
        self.logger.info("is_root: start")
        try:
            stdout, stderr = self.shell_auto(cmd='id', device=device, timeout=5)
        except AdbFailException:
            raise
        if u'uid=0(root)' in stdout:
            self.logger.info("is_root: Now adb %s is root", device)
            return True
        elif u'uid=' in stdout:
            self.logger.info("is_root: Now adb %s is not root - %r", device, stdout)
            return False
        else:
            self.logger.error("is_root: Fail to get response from shell id")
            raise AdbFailException(u"Invalid response from id", stdout, stderr)

    def root_auto(self, device=None):
        '''
        If is_root?
            if not, do root
                    then connect_auto
        If not request to reconnect after root, please use root instead of root_auto
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("root_auto: start")
        try:
            is_root = self.is_root(device=device)
            if is_root:
                self.logger.info("root_auto: Already Root")
                return
        except AdbFailException:
            pass
        try:
            devicename = self.connect_auto(device=device)
            self.root(devicename)
            self.logger.info("root_auto: Root success")
            devicename = self.connect_auto(device=device)
            self.logger.info("root_auto: Re-connect success")
        except AdbFailException:
            raise

    def unroot_auto(self, device=None):
        '''
        If is_root?
            if yes, do unroot
                    then connect
        If not request to reconnect after unroot, please use unroot instead of unroot_auto
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("unroot_auto: start")
        try:
            is_root = self.is_root(device=device)
            if not is_root:
                self.logger.info("unroot_auto: Already unroot")
                return
        except AdbFailException:
            pass
        try:
            devicename = self.connect_auto(device=device)
            self.unroot(devicename)
            self.logger.info("unroot_auto: unroot success")
            devicename = self.connect_auto(device=device)
            self.logger.info("unroot_auto: Re-connect success")
        except AdbFailException:
            raise

    def remount_auto(self, device=None):
        '''
        Use adb remount
        Do connect_auto first, then remount
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: Result(bool)
                Reason(str)
                stdout[from adb command](str)
                stderr(str)
        '''
        self.logger.info("remount_auto: start")
        try:
            devicename = self.connect_auto(device=device)
            self.root_auto(device=device)
            self.remount(device=devicename)
            self.logger.info("remount_auto: success")
        except AdbFailException:
            raise

    def remount_others_auto(self, target, options, device=None):
        '''
        Use adb shell mount to do remount target parition with params
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               target [parition like /factory](str)
               options [like rw/ro/... (No Space!)](str)
        Output: Result(bool)
                Reason(str)
                stdout[from adb command](str)
                stderr(str)
        '''
        self.logger.info("remount_others_auto: start")
        try:
            self.root_auto(device=device)
            stdout, stderr = self.shell_auto(cmd='mount -o {0},remount {1}'.format(options, target), device=device, timeout=30)
        except AdbFailException:
            raise
        if stdout == u'':
            self.logger.info("remount_others_auto: success")
        else:
            self.logger.error("remount_others_auto: fail in shell")
            error = stdout
            raise AdbFailException(error, stdout, stderr)

    def mount2local(self, mount_device, path, vfstype=None, mount_src=None, device=None, *options):
        '''
        Use adb shell mount to do remount target parition with params
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               path [parition like path='/mnt/media/usb' or path='/mnt/media/nfs'](str)
               mount_device[ mount_device='/dev/sdb' or mount_device='10.70.152.168:/home/xinxin/nfs' or
                             mount_device='//10.70.152.168/home/xinxin/nfs']
               mount_src[ mount_src='busybox' or mount_src='busybox.suid']
               options [like '-o' 'nolock' .. ](str)
        Output: Result(bool)
                Reason(str)
                stdout[from adb command](str)
                stderr(str)
        '''
        lst = []
        if mount_src:
            lst.append(mount_src)
        lst.append('mount')
        if vfstype:
            lst.append('-t')
            lst.append(vfstype)
        if options:
            lst.extend(options)
        lst.append(mount_device)
        lst.append(path)
        cmdlst = ' '.join(lst)
        self.logger.info("cmdlst:{}".format(cmdlst))
        try:
            stdout, stderr = self.shell_auto(cmdlst, device=device, timeout=30)
        except AdbFailException:
            raise
        try:
            res = self.get_partition_status()
        except AdbFailException:
            raise
        if res:
            for mount_prop in res:
                if mount_prop['device'] == mount_device and mount_prop['mount_point'] == path:
                    break
            else:
                raise AdbFailException('mount fail', stdout, stderr)

        else:
            raise AdbFailException('mount fail', stdout, stderr)

    def mount2local_auto(self, mount_device, path, vfstype=None, mount_src=None, device=None, *options):
        stdout, stderr = self.shell_auto(cmd=u'ls -l \'{}\''.format(path), device=device, timeout=5)
        if u'No such file or directory' in stdout+stderr:
            try:
                self.shell_auto(cmd='mkdir {}'.format(path), device=device, timeout=5)
            except AdbFailException:
                raise
        vfstype_ = None
        if ':' in mount_device:
            vfstype_ = 'nfs'
        elif mount_device.startswith('//'):
            vfstype_ = 'smbfs'

        if vfstype != vfstype_ and vfstype != 'None':
            self.logger.warning("I expect vfstype is {},but it is {}".format(vfstype_, vfstype))

        version = self.android_sdk_version_get()
        if version:
            if not vfstype:
                mount_src_ = None
            else:
                mount_src_ = 'busybox'
        else:
            if not vfstype:
                mount_src_ = None
            else:
                stdout, stderr = self.shell_auto(cmd="which busybox.suid", device=device, timeout=10)
                if stdout:
                    mount_src_ = 'busybox.suid'
                else:
                    mount_src_ = None
        if mount_src != mount_src_:
            self.logger.warning("I expect mount_src is {},but it is {}".format(mount_src_, mount_src))

        self.mount2local(mount_device, path, vfstype, mount_src, device, *options)

    def push_auto(self, src, dst, device=None, timeout=FILE_TRANSFORM_TIMEOUT):
        '''
        Try adb connect first, then push
        if push fail, try root, then push again
        if push fail, try remoount, then push again
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               src/dst[can be file/folder absolute/relative path](str)
               timeout(int/float)
               Support all adb push support method
        Output: None
        User should know file path after push
        From push command, cannot judgement dst is folder or file
        '''
        self.logger.info("push_auto: start")
        devicename = self.connect_auto(device=device)
        root_try_flag = False
        remount_try_flag = False
        while 1:
            try:
                self.push(src=src, dst=dst, device=devicename, timeout=timeout)
                self.logger.info("push_auto: success")
                break
            except AdbFailException as err:
                self.logger.error("push_auto: fail")
                if err.msg == PERMISSION_DENY:
                    if not root_try_flag:
                        self.logger.info("push_auto: try root")
                        try:
                            self.root_auto(device=devicename)
                        except AdbFailException:
                            pass
                        root_try_flag = True
                        continue
                elif err.msg == READONLY:
                    if not remount_try_flag:
                        self.logger.info("push_auto: try remount")
                        try:
                            self.remount_auto(device=devicename)
                        except AdbFailException:
                            pass
                        remount_try_flag = True
                        continue
                raise
            break

    def pull_auto(self, src, dst, device=None, timeout=FILE_TRANSFORM_TIMEOUT):
        '''
        Try adb connect first, then pull
        if pull fail, try root, then pull again
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               src/dst[can be file/folder absolute/relative path](str)
               timeout(int/float)
               Support all adb pull support method
        Output: filelist
        '''
        self.logger.info("pull_auto: start")
        devicename = self.connect_auto(device=device)
        root_try_flag = False
        while 1:
            try:
                filelist = self.pull(src=src, dst=dst, device=devicename, timeout=timeout)
                self.logger.info("pull_auto: success")
                return filelist
            except AdbFailException as err:
                if err.msg == PERMISSION_DENY:
                    if not root_try_flag:
                        self.logger.info("pull_auto: try root")
                        self.root_auto(device=devicename)
                        root_try_flag = True
                        continue
                raise
            break

    def bugreport_auto(self, filename=None, device=None, timeout=BUGREPORT_TIMEOUT):
        '''
        Try adb connect first, then bugreport
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               filename [Write bugreport into file]
        Output: bugreport(bugreport str and filename=None /
                          full filepath filename!=None
        '''
        self.logger.info("bugreport_auto: start")
        devicename = self.connect_auto(device=device)
        res = self.bugreport(filename=filename, device=devicename, timeout=timeout)
        self.logger.info("bugreport_auto: success")
        return res

    def reboot_auto(self, mode=None, device=None):
        '''
        Do adb connect first, then reboot (Normal|bootloader|recovery|sideload|fastboot)
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               mode [None(for normal reboot) / bootloader / recovery /
                     sideload(require root) / sideload-auto-reboot / fastboot]
        Output: None
        '''
        self.logger.info("reboot_auto: start")
        devicename = self.connect_auto(device=device)
        self.reboot(mode=mode, device=devicename)
        self.logger.info("reboot_auto: success")

    def install_auto(self, apkfile, forward=False, replace=False, test=False,
                     sdcard=False, downgrade=False, permission=False,
                     timeout=FILE_TRANSFORM_TIMEOUT, device=None):
        '''
        Do adb connect first, then install
        Input: apkfile [apk file path](str)
               forward: [-l: forward lock application](bool)
               replace [-r: replace existing application](bool)
               test [-t: allow test packages](bool)
               sdcard [-s: install application on sdcard](bool)
               downgrade [-d: allow version code downgrade](bool)
               timeout (int/float)
               device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        Note: Some Android System need press OK for verify application
              Sugguest close this option in Android System first before use adb install
              Or you need ignore this function return and wait timeout
        '''
        self.logger.info("install_auto: start")
        devicename = self.connect_auto(device=device)
        self.install(apkfile=apkfile, forward=forward, replace=replace, test=test,
                     sdcard=sdcard, downgrade=downgrade, permission=permission,
                     timeout=timeout, device=devicename)
        self.logger.info("install_auto: success")

    def uninstall_auto(self, package, keepdata=False,
                       timeout=FILE_TRANSFORM_TIMEOUT, device=None):
        '''
        Do adb connect first, then uninstall
        Input: package [Application package name](str)
               keepdata: [-k: keep data and cache](bool)
               device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("uninstall_auto: start")
        devicename = self.connect_auto(device=device)
        self.uninstall(package, keepdata=keepdata, timeout=timeout, device=devicename)
        self.logger.info("uninstall_auto: success")

    def disable_verity_auto(self, device=None):
        '''
        Do adb connect auto first, then disable-verity
        If fail, try root, then disable-verity again
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("disable_verity_auto: start")
        devicename = self.connect_auto(device=device)
        root_try_flag = False
        while 1:
            try:
                self.disable_verity(device=devicename)
                self.logger.info("disable_verity_auto: success")
                break
            except AdbFailException as err:
                if err.msg == PERMISSION_DENY:
                    if not root_try_flag:
                        self.logger.info("disable_verity_auto: try root")
                        self.root_auto(device=devicename)
                        root_try_flag = True
                        continue
                raise
            break

    def enable_verity_auto(self, device=None):
        '''
        Do adb connect auto first, then enable-verity
        If fail, try root, then enable-verity again
        if success, need reboot to take effect
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("enable_verity_auto: start")
        devicename = self.connect_auto(device=device)
        root_try_flag = False
        while 1:
            try:
                self.enable_verity(device=devicename)
                self.logger.info("enable_verity_auto: success")
                break
            except AdbFailException as err:
                if err.msg == PERMISSION_DENY:
                    if not root_try_flag:
                        self.logger.info("enable_verity_auto: try root")
                        self.root_auto(device=devicename)
                        root_try_flag = True
                        continue
                raise
            break

    def logcat_auto(self, filename, params=None, device=None):
        '''
        Do adb connect auto first, then logcat, save stdout to filename
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               filename [Full file path](str)
               params [logcat's params, see logcat --help, but don't use -f](str)
        Output: Result(bool)
                Reason(str[Result == False]) / AdbLogcat[Result == True]
        '''
        self.logger.info("logcat_auto: start")
        devicename = self.connect_auto(device=device)
        res, result = self.logcat(filename=filename, params=params, device=devicename)
        if res:
            self.logger.info("logcat_auto: success")
        else:
            self.logger.error("logcat_auto: fail")
        return res, result

    def shell2file_auto(self, filename, cmd, block=False, timeout=60, device=None):
        '''
        Do adb connect first, then shell cmd, save stdout to filename
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               filename [Full file path](str)
               cmd [Any command can run in adb shell such as dmesg/top](str)
               block [Wait command to exit or not](bool)
               timeout [If block == True, timeout for cmd](int)
        Output: Result(bool)
                Reason(str[Result == False]) / AdbLogcat[Result == True]
        '''
        self.logger.info("shell2file_auto: start")
        devicename = self.connect_auto(device=device)
        res, result = self.shell2file(filename=filename, cmd=cmd, device=devicename)
        if res:
            self.logger.info("shell2file_auto: success")
            if block:
                self.logger.debug("block True")
                result.join(timeout=timeout)
                self.logger.debug("shell2file_auto cmd done")
                result.close()
                return res, result
        else:
            self.logger.error("shell2file_auto: fail")
        return res, result

    def android_getprop(self, key, device=None):
        '''
        Use adb shell getprop
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               key(str)
        Output: stdout[from adb command](str)
        '''
        self.logger.info("getprop: start - %s", key)
        stdout, stderr = self.shell_auto(cmd='getprop {}'.format(key), device=device, timeout=5)
        if not stderr:
            self.logger.warning("stderr: %r", stderr)
        self.logger.info("getprop - %s: %r", key, stdout)
        return stdout

    def android_setprop(self, key, value, device=None):
        '''
        Use adb shell setprop
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               key(str)
               value(str)
        Output: None
        '''
        self.logger.info("setprop: start - %s: %s", key, value)
        stdout, stderr = self.shell_auto(cmd='setprop {} {}'.format(key, value), device=device, timeout=5)
        if not stderr:
            self.logger.warning("stderr: %r", stderr)
        self.logger.info("setprop - %s: %r", key, stdout)
        if stdout.strip() == '' and not stderr:
            return None
        self.logger.error("setprop Fail")
        self.logger.error("stdout: %r", stdout)
        self.logger.error("stderr: %r", stderr)
        raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def android_sdk_version_get(self, device=None):
        '''
        Use adb shell getprop ro.build.version.sdk
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: Result(bool)
                Version[If result==True](int) or Reason(str)
                stdout[from adb command](str)
                stderr(str)
        '''
        self.logger.info("get_android_sdk_version: start")
        stdout, stderr = self.shell_auto(cmd='getprop ro.build.version.sdk', device=device, timeout=5)
        version_r = re.search(r'^(\d+)$', stdout)
        if version_r:
            version = version_r.group(1)
            self.logger.info("get_android_sdk_version: %s", version)
            return int(version)
        else:
            self.logger.error("get_android_sdk_version: Fail to get version")
            self.logger.error("stdout: %r", stdout)
            self.logger.error("stderr: %r", stderr)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def pm_list_packages(self, device=None):
        '''
        Do pm list packages
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: Result(bool)
                set(packages)[If result==True](int) or Reason(str)
                stdout[from adb command](str)
                stderr(str)
        '''
        self.logger.info("pm_list_packages: start")
        self.connect_auto(device)
        cmd = u'pm list packages'
        stdout, stderr = self.shell_auto(cmd=cmd, device=device, timeout=30)
        packages = set(re.findall(r'package:([\w\.]*)', stdout))
        if packages:
            return True, packages, stdout, stderr
        else:
            self.logger.error("pm_list_packages: Fail to get packages")
            self.logger.error("stdout: %r", stdout)
            self.logger.error("stderr: %r", stderr)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def pm_disable(self, activity, device=None):
        '''
        Do pm disable for activity
        Input:  activity
                device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("pm_disable: start")
        self.connect_auto(device)
        cmd = u'pm disable {}'.format(activity)
        stdout, stderr = self.shell_auto(cmd=cmd, device=device, timeout=30)
        if u'new state: disabled' in stdout:
            pass
        else:
            self.logger.error("pm_disable: Fail to run")
            self.logger.error("stdout: %r", stdout)
            self.logger.error("stderr: %r", stderr)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def pm_enable(self, activity, device=None):
        '''
        Do pm enable for activity
        Input:  activity
                device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("pm_enable: start")
        self.connect_auto(device)
        cmd = u'pm enable {}'.format(activity)
        stdout, stderr = self.shell_auto(cmd=cmd, device=device, timeout=30)
        if u'new state: enable' in stdout:
            pass
        else:
            self.logger.error("pm_enable: Fail to run")
            self.logger.error("stdout: %r", stdout)
            self.logger.error("stderr: %r", stderr)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def settings_put(self, namespace, key, value, tag=None, default=False, user=None, device=None):
        '''
        Do settings provider command put
        Input:  namespace: [Can be global/secure/system/panel](str)
                key: [setting's key]
                    Refer https://developer.android.com/reference/android/provider/Settings.System#constants
                          https://developer.android.com/reference/android/provider/Settings.Secure#constants
                          https://developer.android.com/reference/android/provider/Settings.Panel#constants
                          https://developer.android.com/reference/android/provider/Settings.Global#constants
                value: [target value](str)
                user: [default follow command define, should be current, can change to other userid](str)
                device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("settings_put: start - (%s)%s", namespace, key)
        cmd = ['settings', 'put']
        if user:
            cmd.extend(['--user', str(user)])
        cmd.extend([str(namespace), str(key), str(value)])
        if tag:
            cmd.append(tag)
        if default:
            cmd.append('default')
        stdout, stderr = self.shell_auto(cmd=' '.join(cmd), device=device, timeout=5)
        if stderr:
            self.logger.error("settings_put error")
            self.logger.error("stdout: %r", stdout)
            self.logger.error("stderr: %r", stderr)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)
        self.logger.info("settings_put: done - (%s)%s: %s", namespace, key, value)

    def settings_get(self, namespace, key, user=None, device=None):
        '''
        Do settings provider command get
        Input:  namespace: [Can be global/secure/system/panel](str)
                key: [setting's key]
                    Refer https://developer.android.com/reference/android/provider/Settings.System#constants
                          https://developer.android.com/reference/android/provider/Settings.Secure#constants
                          https://developer.android.com/reference/android/provider/Settings.Panel#constants
                          https://developer.android.com/reference/android/provider/Settings.Global#constants
                user: [default follow command define, should be current, can change to other userid](str)
                device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: value
        '''
        self.logger.info("settings_get: start - (%s)%s", namespace, key)
        cmd = ['settings', 'get']
        if user:
            cmd.extend(['--user', str(user)])
        cmd.extend([str(namespace), str(key)])
        stdout, stderr = self.shell_auto(cmd=' '.join(cmd), device=device, timeout=5)
        self.logger.info("settings_get - (%s)%s: %r", namespace, key, stdout)
        if stderr.strip():
            self.logger.error("settings_get error")
            self.logger.error("stdout: %r", stdout)
            self.logger.error("stderr: %r", stderr)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)
        if stdout == 'null':
            return None
        return stdout

    def settings_delete(self, namespace, key, user=None, device=None):
        '''
        Do settings provider command delete
        Input:  namespace: [Can be global/secure/system/panel](str)
                key: [setting's key]
                    Refer https://developer.android.com/reference/android/provider/Settings.System#constants
                          https://developer.android.com/reference/android/provider/Settings.Secure#constants
                          https://developer.android.com/reference/android/provider/Settings.Panel#constants
                          https://developer.android.com/reference/android/provider/Settings.Global#constants
                user: [default follow command define, should be current, can change to other userid](str)
                device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("settings_delete: start - %s", key)
        cmd = ['settings', 'delete']
        if user:
            cmd.extend(['--user', str(user)])
        cmd.extend([str(namespace), str(key)])
        stdout, stderr = self.shell_auto(cmd=' '.join(cmd), device=device, timeout=5)
        if not stderr:
            self.logger.warning("stderr: %r", stderr)
        self.logger.info("settings_delete - (%s)%s", namespace, key)
        if re.search(r'Deleted .*? rows', stdout):
            return
        self.logger.error("settings_delete error")
        self.logger.error("stdout: %r", stdout)
        self.logger.error("stderr: %r", stderr)
        raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def settings_reset(self, namespace, package_name=None, reset_mode=None, user=None, device=None):
        '''
        Do settings provider command reset
        Input:  namespace: [Can be global/secure/system/panel](str)
                package_name: [don't complaint with reset_mode](str)
                reset_mode: [Can be untrusted_defaults/untrusted_clear/trusted_defaults](str)
                user: [default follow command define, should be current, can change to other userid](str)
                device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("settings_reset: start - %s", namespace)
        cmd = ['settings', 'reset']
        if user:
            cmd.extend(['--user', str(user)])
        cmd.append(str(namespace))
        if package_name:
            cmd.append(str(package_name))
        if reset_mode:
            cmd.append(str(reset_mode))
        stdout, stderr = self.shell_auto(cmd=' '.join(cmd), device=device, timeout=5)
        if stderr:
            self.logger.error("settings_reset error")
            self.logger.error("stdout: %r", stdout)
            self.logger.error("stderr: %r", stderr)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)
        self.logger.info("settings_reset: done - %s", namespace)

    def settings_list(self, namespace, user=None, device=None):
        '''
        Do settings provider command list
        Input:  namespace: [Can be global/secure/system/panel](str)
                user: [default follow command define, should be current, can change to other userid](str)
                device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: items [dict, key for key in namespace, value for related value]
        '''
        self.logger.info("settings_list: start - %s", namespace)
        cmd = ['settings', 'list']
        if user:
            cmd.extend(['--user', str(user)])
        cmd.append(str(namespace))
        stdout, stderr = self.shell_auto(cmd=' '.join(cmd), device=device, timeout=5)
        if stderr.strip():
            self.logger.error("settings_list error")
            self.logger.error("stdout: %r", stdout)
            self.logger.error("stderr: %r", stderr)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)
        items = {}
        for match in re.finditer(r'((?P<key>[^=]+)=(?P<value>.*))', stdout):
            key = match.groupdict()['key']
            value = match.groupdict()['value'].strip()
            if value == 'null':
                value = None
            items.update({key.strip(): value})
        self.logger.info("settings_list - %s(%s)", namespace, len(items))
        return items

    def get_wakelocks(self, device=None):
        '''
        Get wakelock list from /sys/power/wake_lock
        Input:  device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: wakelocks [wakelock name](set)
        '''
        wakelock_pattern = re.compile(r'===([\w\.]+)!!!')
        cmd = 'for wakelock in $(cat /sys/power/wake_lock); do echo ===${wakelock}!!!; done'
        stdout, stderr = self.shell_auto(cmd=cmd, device=device, timeout=5)
        if stderr:
            self.logger.error("get_wakelocks error")
            self.logger.error("stdout: %r", stdout)
            self.logger.error("stderr: %r", stderr)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)
        wakelocks = set()
        for match in wakelock_pattern.finditer(stdout):
            wakelocks.add(match.group(1))
        if wakelocks:
            self.logger.info("get_wakelocks success")
        return wakelocks

    def file_property(self, filepath, timeformat='%Y-%m-%d %H:%M', device=None):
        '''
        Get target filepath property by 'ls -al' or 'ls -alZ'
        For folder, filepath cannot endwith /
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               filepath [sugguest to Absolute path, folder path is not support](str)
               timeformat [Python datetime.strptime format](str)
        Output: Result(bool)
                file_property_dict(Result=True) / Reason(str)
                stdout[from adb command](str)
                stderr(str)
        file_property_dict: {'permission': 'drwxr-xr-x',
                             'owner':'root', 'group':'root',
                             'filesize':'5', 'datetime': datetime,
                             'filename': '', linkfile:'',
                             # below for SELinux
                             'user': user, u'role': role,
                             'type': setype, u'level': level,
                             }
        '''
        self.logger.info("file_property: start")
        self.root_auto(device)
        file_property_re = self.file_property_nose_re
        try:
            if self.android_sdk_version_get(device=device) > 22:
                cmd = u'ls -alZ \'{}\''.format(filepath)
                file_property_re = self.file_property_se_re
            else:
                cmd = u'ls -al \'{}\''.format(filepath)
        except AdbFailException:
            cmd = u'ls -al \'{}\''.format(filepath)
        stdout, stderr = self.shell_auto(cmd=cmd, device=device, timeout=5)
        property_num = len(file_property_re.findall(stdout))
        if property_num > 1:
            raise AdbFailException(u"Don't Support Multi files", stdout, stderr)
        elif property_num == 0:
            raise AdbFailException(NOFILEORFOLDER, stdout, stderr)
        property_group = file_property_re.search(stdout)
        ret = property_group.groupdict()
        ret.update({u'datetime': datetime.strptime(ret.get(u'datetime'), timeformat)})
        if u' -> ' in ret.get(u'filename'):
            filename, linkfile = ret.get(u'filename').split(u' -> ', 1)
            ret.update({
                u'filename': filename,
                u'linkfile': linkfile,
            })
        if ret.get('seprop'):
            user, role, setype, level = ret.get(u'seprop').split(u':', 4)
            ret.update({
                u'user': user, u'role': role,
                u'type': setype, u'level': level,
            })
        return ret

    def file_exist(self, filepath, device=None):
        '''
        Check file exist or not by ls
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               filepath [sugguest to Absolute path](str)
        Output: bool
        '''
        try:
            self.file_property(filepath=filepath, device=device)
            return True
        except AdbFailException as err:
            if NOFILEORFOLDER in str(err):
                return False
            raise

    def file_remove(self, filepath, device=None):
        '''
        Use rm -rf to delete target
        For folder, filepath cannot endwith /
        Check file exist first
        If exist use rm -f file
        Then check file exist again
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               filepath [sugguest to Absolute path](str)
        Output: None
        '''
        self.logger.info("file_remove: start")
        try:
            self.root_auto(device)
            if self.file_exist(filepath=filepath, device=device):
                self.logger.info("file_remove: try to delete")
                self.shell_auto(cmd='rm -rf \'{}\''.format(filepath), device=device, timeout=60)
                if not self.file_exist(filepath=filepath, device=device):
                    self.logger.info("file_remove: success")
                    return
        except AdbFailException as err:
            if err.msg == NOFILEORFOLDER:
                self.logger.info("file_remove: file no exist")
                return
            raise

    def file_find(self, filename, device=None, timeout=None):
        '''
        Use find command get filepath list
        For folder, filepath cannot endwith /
        To prevent permission deny, will try to do root first
        Note: There is no "find" in Android L or lower, need push busybox and alias find to system PATH
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               filepath [sugguest to Absolute path](str)
               timeout [None for inifite](int)
        Output: Result(bool)
                Filepath List [Result=True](list) / Reason (str)
                stdout[from adb command](str)
                stderr(str)
        '''
        self.logger.info("file_find: start")
        self.root_auto(device)
        stdout, stderr = self.shell_auto('find / -name \'{}\''.format(filename), device=device, timeout=timeout)
        filelist = re.findall(r'^(\.\/.*)$', stdout)
        if len(filelist) < 1:
            self.logger.info("file_find: no target find")
            raise AdbFailException(NOFILEORFOLDER, stdout, stderr)
        else:
            for filepath in filelist:
                self.logger.info("file_find: %s", filepath)
            return filelist

    def file_chmod(self, filename, permission, device=None):
        '''
        Use chmod command change file/folder property
        For folder, filepath cannot endwith /
        To prevent permission deny, will try to do root first
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               filepath [sugguest to Absolute path](str)
               permission [number such as 777 or a+w](str)
        Output: Result(bool)
                Reason (str)
                stdout[from adb command](str)
                stderr(str)
        '''
        self.logger.info("file_chmod: start")
        self.root_auto(device)
        stdout, stderr = self.shell_auto('chmod {0} \'{1}\''.format(permission, filename), device=device, timeout=5)
        if stdout == u'':
            self.logger.info("file_chmod: success")
        else:
            self.logger.info("file_chmod: fail - %s", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def file_link(self, target, filename, params=None, device=None):
        '''
        Use ln command link file/folder
        For folder, filepath cannot endwith /
        To prevent permission deny, will try to do root first
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               target [target link file path, sugguest to Absolute path](str)
               filename [new link file path, sugguest to Absolute path](str)
               params [such as -s or -sfnv](str)
        Output: Result(bool)
                Reason (str)
                stdout[from adb command](str)
                stderr(str)
        '''
        self.logger.info("file_link: start")
        self.root_auto(device)
        if params is None:
            _params = ''
        else:
            _params = params
        stdout, stderr = self.shell_auto('ln {0} \'{1}\' \'{2}\''.format(_params, target, filename), device=device, timeout=5)
        if stdout == u'':
            self.logger.info("file_link: success")
        else:
            self.logger.info("file_link: %s", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def file_alias(self, cmd, target, device=None):
        '''
        Use alias command set temp alias
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               target [short command for alias](str)
               cmd [complete command to alias](str)
        Output: None
        '''
        self.logger.info("file_alias: start")
        self.root_auto(device)
        stdout, stderr = self.shell_auto('alias \'{0}\'=\'{1}\''.format(target, cmd), device=device, timeout=5)
        if stdout == u'':
            self.logger.info("file_alias: success")
        else:
            self.logger.info("file_alias: %s", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def folder_create(self, folderpath, device=None):
        '''
        Use mkdir -p command create folder
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               folderpath [sugguest to Absolute path](str)
        Output: None
        '''
        self.logger.info("folder_create: start")
        self.root_auto(device)
        stdout, stderr = self.shell_auto('mkdir -p \'{}\''.format(folderpath), device=device, timeout=5)
        if stdout == u'':
            self.logger.info("folder_create: success")
        else:
            self.logger.info("folder_create: %r", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def busybox_exist(self, device=None):
        '''
        Check system path include busybox and can be executed
        Check method is to run busybox and check whether output contain BusyBox
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: Result(bool)
        '''
        self.logger.info("busybox_exist: start")
        self.root_auto(device)
        stdout, stderr = self.shell_auto('busybox', device=device, timeout=5)
        if u'Busybox' in stdout:
            self.logger.info("busybox_exist: success")
            res = True
        elif u'not found' in stdout:
            self.logger.info("busybox_exist: fail to found")
            res = False
        else:
            self.logger.info("busybox_exist: %r", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)
        return res

    def interface_list_get(self, device=None):
        '''
        Try root first, for Android system, only root can get status from ifconfig/netcfg
        Check Android SDK version, if lower than 23, use netcfg
                                   else, use ifconfig
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: Interfaces (set)
        Interfaces: ({u'interface': u'eth0',
                      u'ip': u'10.37.132.131',
                      u'mac': u'00:11:22:33:44:55'},
                     {u'interface': u'wlan0',
                      u'ip': u'192.168.1.241',
                      u'mac': u'55:44:33:22:11:00'})
        '''
        self.logger.info("interface_list_get: start")
        self.root_auto(device=device)
        try:
            version = self.android_sdk_version_get(device=device)
        except AdbFailException:
            self.logger.info("None-Android platform, may try ifconfig directly")
            interface_re = self.ifconfig_re
            cmd = u'ifconfig'
        else:
            if version < 23:
                self.logger.info("interface_list_get: target system Android Version <= 5.0 (SDK 22)")
                interface_re = self.netcfg_re
                cmd = u'netcfg'
            else:
                self.logger.info("interface_list_get: target system Android Version >= 6.0 (SDK 23) or other Linux System")
                interface_re = self.ifconfig_re
                cmd = u'ifconfig'
        stdout, stderr = self.shell_auto(cmd, device=device, timeout=5)
        interfaces_list = []
        if not interface_re.search(stdout):
            self.logger.warning("Fail to find any network interface")
            self.logger.warning("stdout: %r", stdout)
            self.logger.warning("stderr: %r", stderr)
        else:
            for interface in interface_re.finditer(stdout):
                interfaces_list.append({
                    u'interface': interface.group(u'interfacename'),
                    u'mac': interface.group(u'mac'),
                    u'driver': interface.group(u'driver'),
                    u'ip': interface.group(u'ip'),
                    u'bcast': interface.group(u'bcast'),
                    u'mask': interface.group(u'mask'),
                })
                self.logger.info("Find: %5s|%17s|%s",
                                 interface.group(u'interfacename'),
                                 interface.group(u'mac'),
                                 interface.group(u'ip'))
        self.logger.info("interface_list_get: end")
        return interfaces_list

    def interface_mapping(self, source, target, source_content, device=None):
        '''
        Return target according source with source content
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               source/target [ip/interface/mac](str)
               source_content [source's content, such as eth0/192.168.1.2](str)
        Output: False / target_content (str)
        '''
        self.logger.info("interface_mapping: start")
        self.logger.info("interface_mapping: source_content - %s", source_content)
        assert source in (u'ip', 'interface', 'mac'), u"Invalid source, should be ip/interface/mac"
        assert target in (u'ip', 'interface', 'mac'), u"Invalid target, should be ip/interface/mac"
        interface_list = self.interface_list_get(device=device)
        for interface_dict in interface_list:
            if interface_dict[source] == source_content:
                target_content = interface_dict[target]
                self.logger.info("interface_mapping: Get %s - %s", target, target_content)
                return target_content
        self.logger.info("interface_mapping: Fail to find %s according %s", target, source)
        return False

    def interface_according_ip_get(self, ip, device=None):
        '''
        Return interface according IP
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               ip (str)
        Output: False / Interface (str)
        '''
        return self.interface_mapping(u'ip', u'interface', ip, device=device)

    def interface_according_mac_get(self, mac, device=None):
        '''
        Return interface according mac
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               mac (str)
        Output: False / Interface (str)
        '''
        return self.interface_mapping(u'mac', u'interface', mac, device=device)

    def ip_according_interface_get(self, interface, device=None):
        '''
        Return IP according interface
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               interface (str)
        Output: False / ip (str)
        '''
        return self.interface_mapping(u'interface', u'ip', interface, device=device)

    def ip_according_mac_get(self, mac, device=None):
        '''
        Return IP according mac
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               mac (str)
        Output: False / ip (str)
        '''
        return self.interface_mapping(u'mac', u'ip', mac, device=device)

    def mac_according_interface_get(self, interface, device=None):
        '''
        Return mac according interface
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               interface (str)
        Output: False / mac (str)
        '''
        return self.interface_mapping(u'interface', u'mac', interface, device=device)

    def mac_according_ip_get(self, ip, device=None):
        '''
        Return mac according ip
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               interface (str)
        Output: False / mac (str)
        '''
        return self.interface_mapping(u'ip', u'mac', ip, device=device)

    def get_process_list(self, ps_type=u'Android', device=None):
        '''
        Return process list from ps
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               ps_type [Android/BusyBox] (str)
        Output: process_list (set)
        For Android, run command: ps
        For BusyBox, run command: busybox ps (Please confirm busybox in system PATH)
        Process List = [  #Android ps
                          {u'pid': pid(str),
                           u'user': user(str),
                           u'ppid': ppid(str),
                           u'vsize': vsize(int), # By default, it should be kilobyte
                           u'rss': rss(int), # By default, it should be kilobyte
                           u'wchan': wchan(str),
                           u'pc': pc(str),
                           u'statecode': statecode(str),
                           u'name': name(str)}

                          #BusyBox ps
                          {u'pid': pid(str),
                           u'userid': userid(str),
                           u'time': time(str),
                           u'comamnd': command(str)}
                       ]
        '''
        assert ps_type in (u'Android', u'BusyBox')
        self.logger.info("get_process_list: start")
        if ps_type == u'Android':
            ps_re = self.android_ps_re
            cmd = 'ps'
            param_list = [u'user', u'pid', u'ppid', u'vsize', u'rss', u'wchan', u'pc', u'statecode', u'name']
        else:
            if self.busybox_exist(device=device):
                raise AdbFailException(u'No Busybox Found', None, None)
            ps_re = self.busybox_ps_re
            cmd = 'busybox ps'
            param_list = [u'pid', u'userid', u'time', u'command']
        stdout, stderr = self.shell_auto(cmd, device=device, timeout=5)
        result_re = ps_re.findall(stdout)
        if len(result_re) < 1:
            self.logger.error("get_process_list: no process find, abnormal")
            raise AdbFailException(u'no process find', stdout, stderr)
        else:
            processes_list = []
            for process_list in result_re:
                processes_list.append(dict(zip(param_list, process_list)))
            self.logger.info("get_process_list: success")
            return set(processes_list)

    def get_contacts(self, device=None):
        '''
        Return contacts
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: contacts (list)
        contacts List = [{   if NULL, switch to python None, others are string
            phonetic_name': (str),
            custom_ringtone': (str),
            contact_status_ts': (str),
            pinned': (str),
            photo_id': (str),
            photo_file_id': (str),
            contact_status_res_package': (str),
            contact_chat_capability': (str),
            contact_status_icon': (str),
            display_name_alt': (str),
            sort_key_alt': (str),
            in_visible_group': (str),
            starred': (str),
            contact_status_label': (str),
            phonebook_label': (str),
            is_user_profile': (str),
            has_phone_number': (str),
            display_name_source': (str),
            phonetic_name_style': (str),
            send_to_voicemail': (str),
            lookup': (str),
            phonebook_label_alt': (str),
            contact_last_updated_timestamp': (str),
            photo_uri': (str),
            phonebook_bucket': (str),
            contact_status': (str),
            display_name': (str),
            sort_key': (str),
            photo_thumb_uri': (str),
            contact_presence': (str),
            in_default_directory': (str),
            times_contacted': (str),
            _id': (str),
            name_raw_contact_id': (str),
            phonebook_bucket_alt': (str),
        }]
        '''
        self.logger.info("get_contacts: start")
        stdout, stderr = self.shell_auto('content query --uri content://com.android.contacts/contacts', device=device, timeout=60)
        # Samples:
        #     Row: 0 last_time_contacted=0, phonetic_name=NULL, custom_ringtone=NULL, contact_status_ts=NULL, pinned=0, photo_id=NULL, photo_file_id=NULL, contact_status_res_package=NULL, contact_chat_capability=NULL, contact_status_icon=NULL, display_name_alt=name_extensions_test_stub, sort_key_alt=name_extensions_test_stub, in_visible_group=1, starred=0, contact_status_label=NULL, phonebook_label=N, is_user_profile=0, has_phone_number=0, display_name_source=40, phonetic_name_style=0, send_to_voicemail=0, lookup=759i4d70e8c70947fad4, phonebook_label_alt=N, contact_last_updated_timestamp=1592833993560, photo_uri=NULL, phonebook_bucket=14, contact_status=NULL, display_name=name_extensions_test_stub, sort_key=name_extensions_test_stub, photo_thumb_uri=NULL, contact_presence=NULL, in_default_directory=1, times_contacted=0, _id=1, name_raw_contact_id=1, phonebook_bucket_alt=14
        #     Row: 1 last_time_contacted=0, phonetic_name=NULL, custom_ringtone=NULL, contact_status_ts=NULL, pinned=0, photo_id=NULL, photo_file_id=NULL, contact_status_res_package=NULL, contact_chat_capability=NULL, contact_status_icon=NULL, display_name_alt=Alice, sort_key_alt=Alice, in_visible_group=1, starred=0, contact_status_label=NULL, phonebook_label=A, is_user_profile=0, has_phone_number=1, display_name_source=40, phonetic_name_style=0, send_to_voicemail=0, lookup=759i6d1c3b9a8d73e2a5, phonebook_label_alt=A, contact_last_updated_timestamp=1592890550479, photo_uri=NULL, phonebook_bucket=1, contact_status=NULL, display_name=Alice, sort_key=Alice, photo_thumb_uri=NULL, contact_presence=NULL, in_default_directory=1, times_contacted=0, _id=6, name_raw_contact_id=2, phonebook_bucket_alt=1
        contacts = []
        if 'No result found.' in stdout.strip() + stderr.strip():
            self.logger.info("get_contacts: No result found.")
            return []
        for line in (stdout.strip() + stderr.strip()).split('\n'):
            if not line.strip():
                continue
            line = line.split(': ', 1)[-1].split(' ', 1)[-1]
            contact = {}
            for key_value in line.split(','):
                if key_value.count('=') < 1:
                    continue
                key, value = key_value.split('=', 1)
                key, value = key.strip(), value.strip()
                if value == 'NULL':
                    value = None
                contact[key] = value
            contacts.append(contact)
        self.logger.info("get_contacts: %d", len(contacts))
        return contacts

    def del_contact(self, contact_id, device=None):
        '''
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               contact_id [contact to delete](str)
        '''
        self.logger.info("del_contacts: start")
        cmd = 'content delete --uri content://com.android.contacts/contacts/{}'.format(contact_id)
        stdout, stderr = self.shell_auto(cmd, device=device, timeout=60)
        if stdout.strip() + stderr.strip():
            self.logger.error("del_contacts: fail")
            if stdout.strip():
                self.logger.error("stdout: %r", stdout)
            if stderr.strip():
                self.logger.error("stderr: %r", stderr)
            raise AdbFailException(u'delete contact fail', stdout, stderr)
        self.logger.info("del_contacts: done")

    def get_partition_status(self, device=None):
        '''
        Return mount status from mount command
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: mount_list (set)
        Mount List = [
                          {u'device': (str),
                           u'mount_point': (str),
                           u'type': (str),
                           u'options': vsize(int)},
        ]
        '''
        self.logger.info("mount: start")
        self.root_auto(device)
        stdout, stderr = self.shell_auto('mount', device=device, timeout=30)
        mount_l = self.mount_re.findall(stdout)
        if mount_l:
            mount_dict_list = []
            self.logger.info("mount: success")
            for mount in mount_l:
                mount_dict_list.append({
                    u'device': mount[0],
                    u'mount_point': mount[1],
                    u'type': mount[2],
                    u'options': mount[3]
                })
            return mount_dict_list
        elif u'not found' in stdout:
            self.logger.info("mount: fail to found")
            raise AdbFailException(SHELL_FAILED, stdout, stderr)
        else:
            self.logger.info("mount: %r", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def get_proc_partitions(self, device=None):
        '''
        Return partitions from /proc/partitions
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: partitions (set)
        [
                          {u'major': int,
                           u'minor': int,
                           u'blocks': int,
                           u'name': str},
        ]
        '''
        self.logger.info("partitions: start")
        self.root_auto(device)
        stdout, stderr = self.shell_auto('cat /proc/partitions', device=device, timeout=30)
        partition_list = re.findall(r'(\d+)\s+(\d+)\s+(\d+)\s+(\w+)', stdout)
        partitions = []
        if partition_list:
            self.logger.info("partitions: success")
            for partition in partition_list:
                partitions.append({
                    u'major': int(partition[0]),
                    u'minor': int(partition[1]),
                    u'blocks': int(partition[2]),
                    u'name': partition[3]
                })
            return partitions
        else:
            self.logger.info("partitions: %r", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def get_android_ext_storages(self, devicename_prefix, device=None):
        '''Get Android External Storages mount point list
        Input: devicename_prefix [for USB Disk, it is sd, for SDCard, it is mmc](str)
               device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: Storage List
                Such as ['/mnt/media_rw/xxxx-yyyy', '/mnt/media_rw/aaaa-bbbb']
        '''
        self.connect_auto(device=device)
        mounts = self.get_partition_status(device=device)
        partitions = self.get_proc_partitions(device=device)
        ext_devices = []
        for mount in mounts:
            mount_point = mount.get('mount_point', '')
            device_path = mount.get('device', '')
            if '/mnt/media_rw' not in mount_point:
                continue
            if ':' not in device_path:
                continue
            major, minor = device_path.split(':')[-1].split(',', 2)
            for partition in partitions:
                if major == str(partition.get('major', 0)) and minor == str(partition.get('minor', 0)):
                    if partition.get('name', '').startswith(devicename_prefix):
                        ext_devices.append(mount_point)
        return ext_devices

    def get_android_usbdisks(self, device=None):
        return self.get_android_ext_storages('sd', device=device)

    def get_android_sdcards(self, device=None):
        return self.get_android_ext_storages('mmc', device=device)

    def input_keyevent(self, keycode, longpress=False, device=None, timeout=5):
        '''
        Use android command: input keyevent
        Input:  keycode (str/int) See Android Formal Page
                device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("input_keyevent: start")
        if longpress:
            cmd = 'input keyevent --longpress {}'.format(keycode)
        else:
            cmd = 'input keyevent {}'.format(keycode)
        stdout, stderr = self.shell_auto(cmd, device=device, timeout=timeout)
        if stdout == u'':
            self.logger.info("input_keyevent: success")
        else:
            self.logger.info("input_keyevent: %s", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def input_tap(self, x, y, device=None, timeout=5):
        '''
        Use android command: input tap
        Input:  x/y (int)
                device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("input_tap: start")
        stdout, stderr = self.shell_auto('input tap {} {}'.format(x, y), device=device, timeout=timeout)
        if stdout == u'':
            self.logger.info("input_tap: success")
        else:
            self.logger.info("input_tap: %s", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def input_text(self, text, device=None, timeout=5):
        '''
        Use android command: input keyevent
        Input:  text (str)
                device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        self.logger.info("input_text: start")
        stdout, stderr = self.shell_auto('input text {}'.format(text), device=device, timeout=timeout)
        if stdout == u'':
            self.logger.info("input_text: success")
        else:
            self.logger.info("input_text: %s", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def screencap(self, host_path, display_id=None, device=None, timeout=30):
        '''
        Use screencap dump picture, and save to host
        Input: host_path [file path in host to save dump snapshot, must be a png file(str)]
               display_id [parameter pass to screencap(str)]
               device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        '''
        self.logger.info("screencap: start")
        if host_path.split('.')[-1] != u'png':
            raise AdbFailException("Invalid hostpath, must be .png", u'', u'')

        if not os.path.isdir(os.path.dirname(os.path.abspath(host_path))):
            os.makedirs(os.path.dirname(os.path.abspath(host_path)))
        remote_filename = u'screencap_{}.png'.format(datetime.now().strftime('%Y%m%d%H%M%S%f'))
        remote_path = posixpath.join('/data/local/tmp', remote_filename)
        cmd = [u'screencap', '-p']
        if display_id:
            cmd.extend([u'-d', str(display_id)])
        cmd.append(remote_path)
        self.logger.debug("screencap to remote_path")
        stdout, stderr = self.shell_auto(' '.join(cmd), device=device, timeout=timeout)
        content = stdout + stderr
        if u'Error opening file' in content:
            self.logger.error("screencap fail: %s", content.strip())
            raise AdbFailException("screencap Fail", stdout, stderr)
        elif u'Failed to take screenshot' in stdout + stderr:
            self.logger.error("screencap fail: %s", content.strip())
            raise AdbFailException("screencap Fail", stdout, stderr)
        self.logger.debug("screencap pull to host")
        self.pull_auto(remote_path, os.path.abspath(host_path), device=device, timeout=timeout)
        self.logger.debug("screencap delete remote")
        self.file_remove(remote_path, device=device)
        self.logger.info("screencap: success")

    def uiautomator_dump(self, device=None, timeout=30):
        '''
        Use uiautomarot dump, and return xml content
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: XML_Content(str) for uiautomator dump
        '''
        temp_folder = u'/sdcard' # can work on both root/shell
        self.logger.info("uiautomator_dump: start")
        _, stderr = self.shell_auto('uiautomator dump {}/uiautomator.xml'.format(temp_folder), device=device, timeout=timeout)
        stdout, _ = self.shell_auto('cat {}/uiautomator.xml'.format(temp_folder), device=device, timeout=timeout)
        _, _ = self.shell_auto('rm {}/uiautomator.xml'.format(temp_folder), device=device, timeout=timeout)
        if stdout.startswith(u"<?"):
            self.logger.info("uiautomator_dump: success")
            return stdout
        elif u'ERROR:' in stderr:
            self.logger.error("uiautomator_dump %s", stderr)
            raise AdbFailException(stderr.replace(u'ERROR:', ''), stdout, stderr)
        else:
            self.logger.error("uiautomator_dump: %s", stdout)
            raise AdbFailException(SHELL_FAILED, stdout, stderr)

    def dumpsys_audio(self, device=None):
        '''
        Use adb shell dumpsys audio to get volume status
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: audio_infos(dict)
            {
                'volumes': {
                    'STREAM_VOICE_CALL': {
                        'muted': True,
                        'min': 1,
                        'max': 7,
                        'devices': set(['speaker', 'bt_a2dp']),
                        'current': {
                            2:5,  # 1 is device id
                            40000000: 4,
                        }
                    },
                    'STREAM_MUSIC': {
                        ...
                    },
                },
                'device2id': {
                    'speaker': 2,
                    'default': 40000000,
                }
            }
        '''
        self.logger.info("dumpsys audio: start - %s")
        stdout, stderr = self.shell_auto(cmd='dumpsys audio', device=device, timeout=5)
        volume_pattern = re.compile(r'- (?P<path>STREAM_[^:]*):\s*'
                                    r'Muted: (?P<muted>true|false)\s*'
                                    r'Min: (?P<min>\d+)\s*'
                                    r'Max: (?P<max>\d+)\s*'
                                    r'(?:streamVolume:(?P<streamvolume>\d+)\s*)?'
                                    r'Current: (?P<current>[^\r\n]+)\s*'
                                    r'Devices: (?P<devices>[^\r\n]+)\s*'
                                    )
        volume_current_pattern = re.compile(r'(?P<id>\d+)\s*\((?P<name>[^)]+)\):\s*(?P<volume>\d+)')
        volumes = {}
        device2id = {}
        for match in volume_pattern.finditer(stdout+stderr):
            stream_info = {
                u'muted': match.groupdict()[u'muted'] == u'true',
                u'min': int(match.groupdict()[u'min']),
                u'max': int(match.groupdict()[u'max']),
                u'devices': set([device.strip() for device in match.groupdict()[u'devices'].split(',')])
            }
            current = {}
            for match_cur in volume_current_pattern.finditer(match.groupdict()[u'current']):
                current.update({int(match_cur.groupdict()[u'id']): int(match_cur.groupdict()[u'volume'])})
                device2id.update({match_cur.groupdict()[u'name']: int(match_cur.groupdict()[u'id'])})
            stream_info.update({'current': current})
            volumes.update({match.groupdict()[u'path']: stream_info})
        ret = {
            'volumes': volumes,
            'device2id': device2id,
        }
        if not volumes:
            self.logger.error("Invalid dumpsys audio, maybe format changed?")
        return ret

    def _apm_common(self, cmd, name, main, device=None, timeout=10):
        '''
        Basic am/pm control
        '''
        stdout, stderr = self.shell_auto(cmd, device=device, timeout=timeout)
        if u'Success' in stdout:
            self.logger.info("%s %s success", main, name)
            return stdout
        if self.pm_setting_re.search(stdout):
            # For enable/disable
            self.logger.info("%s %s success", main, name)
            return stdout
        reason = 'Unknown Reason'
        if u'Warning: ' in stdout:
            reason = self.warn_re.search(stdout).group(1)
            self.logger.error("%s %s warning: %s", main, name, reason)
        if u'Error: ' in stdout:
            reason = self.error_re.search(stdout).group(1)
            self.logger.error("%s %s error: %s", main, name, reason)
            raise AdbFailException(reason, stdout, stderr)
        if u'Failure [' in stdout:
            reason = self.pm_failure_re.search(stdout).group(1)
            self.logger.error("%s %s failure: %s", main, name, reason)
            raise AdbFailException(reason, stdout, stderr)
        if u'Failed' in stdout:
            self.logger.error("%s %s failed", main, name)
            raise AdbFailException(reason, stdout, stderr)
        self.logger.critical("%s %s unknown status", main, name)
        self.logger.error("%s %s: %r", main, name, stdout)
        raise AdbFailException(reason, stdout, stderr)

    def am_kill(self, package, device=None):
        '''
        Do am kill
        Input: package [Application package name](str)
               device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: None
        '''
        cmd = u'am kill {}'.format(package)
        self._apm_common(cmd, u'kill', u'am', device=device)

    def am_start(self, intent, device=None, timeout=30, **options):
        '''
        Android Activity Manager controller
        Input: intent(str), see https://developer.android.com/studio/command-line/adb.html#IntentSpec
               device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
               options:
                    debugging(bool), enable debugging, default as False
                    wait(bool), Wait for lanch to complete, default as False
                    profiler(str), define profiler file path
                    Profiler(str), define profiler file path, but stop after app goes idle
                    forcestop(bool), force stop target app before starting the activity, default as False
                    userid(str), specify which user to run as, default as current
        Output: stdout(str)
                stderr(str)
                result_dict(dict){
                    error_type(str)
                    error_message(str)
                    status(str)
                    thistime(int)
                    totaltime(int)
                    waittime(int)
                }
        '''
        raise NotImplementedError

        '''
Starting: Intent { act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] pkg=com.arachnoid.sshelper }
Error: Activity not started, unable to resolve Intent { act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] flg=0x10000000 pkg=com.arachnoid.sshelper }

Starting: Intent { act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] cmp=com.android.tv.settings/.MainActivity }
Error type 3
Error: Activity class {com.android.tv.settings/com.android.tv.settings.MainActivity} does not exist.

Starting: Intent { act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] cmp=com.android.tv.settings/.MainSettings }

-W
Starting: Intent { act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] cmp=com.android.tv.settings/.MainSettings }
Warning: Activity not started, its current task has been brought to the front
Status: ok
Activity: com.android.tv.settings/.MainSettings
ThisTime: 0
TotalTime: 0
WaitTime: 7
Complete

-S
Stopping: com.android.tv.settings
Starting: Intent { act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] cmp=com.android.tv.settings/.MainSettings }
        '''

    def pm(self, device=None, timeout=30):
        '''Android Package Manager controller'''
        raise NotImplementedError

    def sm(self, device=None, timeout=30):
        '''Android Package Manager controller'''
        raise NotImplementedError

    def usb_mount_exist(self):
        raise NotImplementedError

    def ping_status(self):
        raise NotImplementedError
