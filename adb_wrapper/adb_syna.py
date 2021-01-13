# -*- coding: utf-8 -*-
import re

from .adb_auto import AdbAuto
from .adb_wrapper import AdbFailException

# /proc/cpm/status regex pattern
CPM_PATTERNS = {
    u'MOD': re.compile(
        r'\d+\s+(?P<name>[A-Za-z0-9]+)'
        r'\s+(?P<status>ON|OFF|-)\s*\(\s*(?P<on>\d+)/\s*(?P<total>\d+)\)'
        r'\s+(?P<startup>OFF|-)'
        r'\s*\n'
        ),
    u'CORE': re.compile(
        r'\d+\s+(?P<name>[A-Za-z0-9]+)'
        r'\s+(?P<status>[A-Z])'
        r'\s+(?P<cfg>Y|N)'
        r'\s*\n'
        ),
    u'CLK SRC': re.compile(
        r'\d+\s+(?P<name>\w+)'
        r'\s+(?P<freq>\d+)MHz'
        r'\s*\n'
        ),
    u'CLK': re.compile(
        r'\d+\s+(?P<name>\w+)'
        r'\s+(?P<freq>\d+)MHz'
        r'\s+(?P<en>ON|OFF)'
        r'\s+(?P<ref>\d+)'
        r'\s*\n'
        ),
    u'PERIPHERAL': re.compile(
        r'\d+\s+(?P<name>\w+)'
        r'\s+(?P<en>ON|OFF)'
        r'\s*\n'
        ),
    u'OTHERS': re.compile(
        r'leakage:\s*(?P<leakage>\d+)mA'
        r'\s+temp:\s*(?P<temp>\d+)'
        r'\s+Vcore:\s*(?P<voltage>\d+)mV'
        r'\s+status:\s*(?P<status>H|M|L)'
        r'\s*\n'
        ),
}

SOC_NAMES = {
    'VS680': 'Synaptics VS680',
    'BG5CT': 'Marvell Berlin BG5CT',
    'BG4CT': 'Marvell Berlin BG4CT',
}

AMP_VIDEO_ID = {
    '16': 'mpeg1',
    '17': 'mpeg2',
    '18': 'h263',
    '19': 'mpeg4',
    '20': 'wmv',
    '21': 'rv',
    '22': 'h264',
    '23': 'mjpeg',
    '24': 'vc1',
    '25': 'vp8',
    '26': 'divx',
    '27': 'xvid',
    '28': 'avs',
    '29': 'sorenson',
    '30': 'div50',
    '31': 'vp6',
    '32': 'rv30',
    '33': 'rv40',
    '34': 'div3',
    '35': 'div4',
    '36': 'h265',
    '37': 'vp9',
    '38': 'av1',
}

class SynaInvalidOutputException(AdbFailException):
    pass

class AdbSyna(AdbAuto):

    _cache = {} # used to cache some result avoid duplicate get

    def cache_set(self, device, key, value):
        if device in self._cache:
            self._cache[device][key] = value
        else:
            self._cache = {device: {key: value}}

    def cache_clear(self, device=None, key=None):
        if device:
            if device not in self._cache:
                return
            if key and key in self._cache[device]:
                del self._cache[device][key]
        else:
            self._cache = {}

    def get_soc_family(self):
        if self._device:
            try:
                soc = self._cache[self._device]['soc']
            except KeyError:
                pass
            else:
                return soc
        cmd = u'cat /sys/devices/soc0/family'
        stdout, stderr = self.shell_auto(cmd, timeout=10)
        content = stdout + stderr
        content = content.strip()
        for name, pattern in SOC_NAMES.items():
            if pattern in content:
                if self._device:
                    self.cache_set(self._device, 'soc', name)
                return name
        self.logger.warning("Unknown SoC: %s", content)
        return None

    def is_vdec_working(self):
        soc = self.get_soc_family()
        if 'VS' in soc:
            vdec = self.mdb_sys_com_5()
            if vdec:
                return vdec['estate_str'] in ('VDEC_STATE_EXECUTING', 'VDEC_STATE_WAIT_INPUT_BUFFER', 'VDEC_STATE_WAIT_OUTPUT_BUFFER')
            self.logger.warning("Invalid vdec state: %r", vdec)
            raise RuntimeError('Invalid vdec state')
        else:
            cpm = self.cpm_status()
            try:
                return cpm['MOD']['V4G']['status'] == 'ON'
            except KeyError:
                self.logger.warning("No V4G status in CPM: %r", cpm)
                raise RuntimeError('Invalid V4G state')

    def mdb_sys_com_5(self):
        # disable selinux first
        cmd = u'mdb sys comp 5'
        stdout, stderr = self.shell(cmd, timeout=10)
        content = stdout + stderr
        pattern = re.compile(
            r'\s*mode:\s*(?P<mode_id>\d+)(?:\((?P<mode_str>\S+)\))?'
            r'\s*uiType:\s*(?P<codec_id>\d+)(?:\((?P<codec_str>\S+)\))?'
            r'\s*uiFlag:\s*(?P<flag>0x[a-f0-9]+)'
            r'\s*Part 2: Decoder info\s*'
            r'\s*eState:\s*(?P<estate_id>\d+)(?:\((?P<estate_str>\S+)\))?'
            r'\s*vpuId:\s*(?P<vpu_id>\d+)(?:\((?P<vpu_str>\S+)\))?'
            r'\s*DecodeMode:\s*(?P<decode_mode_id>\d+)'
            r'\s*(?:max_width:\s*(?P<max_width>\d+))?'
            r'\s*(?:max_height:\s*(?P<max_height>\d+))?'
            r'\s*(?:display W\*H:\s*(?P<display_width>\d+)\*(?P<display_height>\d+))?'
            r'\s*(?:frame W\*H:\s*(?P<frame_width>\d+)\*(?P<frame_height>\d+))?'
            r'\s*frame_rate_num:\s*(?P<frame_rate_num>\d+)'
            r'\s*frame_rate_den:\s*(?P<frame_rate_den>\d+)'
            r'\s*output_mode:\s*(?P<output_mode_id>\d+)(?:\((?P<output_mode_str>\S+)\))?'
        )
        match = pattern.search(content)
        if not match:
            self.logger.warning("Invalid mdb sys comp 5 return: %r", content)
            return {}
        result = match.groupdict()
        modeid = {
            '0': 'tunnel',
            '1': 'non-tunnel',
            '2': 'secure-tunnel',
        } # 'unknown mode'
        if not result['mode_str']:
            result['mode_str'] = modeid.get(result['mode_id'], 'unknown mode')
        if not result['codec_str']:
            result['codec_str'] = AMP_VIDEO_ID.get(result['codec_id'], 'unknown')
        if result['flag']:
            result['flag'] = int(result['flag'], 16)
        # ref: http://10.70.24.134:8080/source/xref/AndroidQ/sdk/ampsdk/amp/src/ddl/vcodec/comp_vdec/source/internal_api_priv.h#124
        estates = {
            '0': 'VDEC_STATE_LOADED',
            '1': 'VDEC_STATE_IDLE',
            '2': 'VDEC_STATE_EXECUTING',
            '3': 'VDEC_STATE_PAUSED',
            '4': 'VDEC_STATE_WAIT_INPUT_BUFFER',
            '5': 'VDEC_STATE_WAIT_OUTPUT_BUFFER',
            '6': 'VDEC_STATE_INTERNAL_ERROR',
            '7': 'VDEC_STATE_FREEZE',
            '8': 'VDEC_STATE_UNFREEZE',
            '9': 'VDEC_STATE_INTERNAL_ERROR',
        }
        if not result['estate_str']:
            result['estate_str'] = estates.get(result['estate_id'], 'UNKNOWN_VDEC_STATE')
        # ref: http://10.70.24.134:8080/source/xref/AndroidQ/sdk/ampsdk/amp/src/ddl/vcodec/vpu_sched/source/vmeta_sched_api.c#113
        vpus = {
            '0': 'VMETA',
            '1': 'V4G',
            '2': 'G2',
            '3': 'G1',
            '4': 'H1',
            '5': 'H1_1',
        }
        if not result['vpu_str']:
            result['vpu_str'] = vpus.get(result['vpu_id'], 'invalid VPU')
        if result['max_width']:
            result['frame_width'] = int(result['max_width'])
            del result['max_width']
        if result['max_height']:
            result['frame_height'] = int(result['max_height'])
            del result['max_height']
        # ref: http://10.70.24.134:8080/source/xref/AndroidQ/sdk/ampsdk/amp/src/ddl/vcodec/vpu_lib/vs680/include/vpu_api.h#276
        formats = {
            '0': 'UYVY',
            '1': 'VYUY',
            '2': 'YUYV',
            '3': 'YVYU',
            '4': 'SPUV',
            '6': 'SPVU',
            '7': 'YUV',
            '8': 'TILE',
            '14': 'TILE2',
            '15': 'MULTI_CHANNEL',
            '16': 'FORMAT_NUM',
        }
        if not result['output_mode_str']:
            result['output_mode_str'] = formats.get(result['output_mode_id'], 'unknown')
        self.logger.info("mdb_sys_comp_5: %r", result)
        return result

    def test_disp(self, args, timeout=5):
        cmd = u'test_disp {}'.format(u' '.join(args))
        stdout, stderr = self.shell_auto(cmd, timeout=timeout)
        return stdout, stderr

    def test_disp_getvidfmt(self):
        '''Get HDMI Tx Color Format / Bit Depth
        Output: {
            'color': '444/422/420/rgb',
            'bitdepth': '8'/'10'/'12'
        }'''
        args = [u'getvidfmt']
        stdout, stderr = self.test_disp(args)
        res = stdout + u'\n' + stderr
        vidfmt = {}
        if u'OUTPUT_COLOR_FMT_' not in res:
            self.logger.warning("Invalid Response: %r", res)
            raise SynaInvalidOutputException
        if u'OUTPUT_BIT_DEPTH_' not in res:
            self.logger.warning("Invalid Response: %r", res)
            raise SynaInvalidOutputException
        if u'OUTPUT_COLOR_FMT_YCBCR444' in res:
            vidfmt[u'color'] = u'444'
        elif u'OUTPUT_COLOR_FMT_YCBCR422' in res:
            vidfmt[u'color'] = u'422'
        elif u'OUTPUT_COLOR_FMT_YCBCR420' in res:
            vidfmt[u'color'] = u'420'
        elif u'OUTPUT_COLOR_FMT_RGB888' in res:
            vidfmt[u'color'] = u'rgb'
        else:
            self.logger.warning("Invalid Color Format: %r", res)
            raise SynaInvalidOutputException
        match = re.search(r'OUTPUT_BIT_DEPTH_(\d+)BIT', res)
        if not match:
            self.logger.warning("Invalid Bit Depth: %r", res)
        vidfmt[u'bitdepth'] = match.group(1)
        return vidfmt

    def test_disp_getres(self):
        '''Get HDMI Tx Resolution / FPS
        Output: {
            'resolution': '1920x1080',
            'is_progress' : True/False
            'fps': '60'/'59'
        }'''
        resolution_mapping = {
            u'525': u'720x480',
            u'625': u'720x576',
            u'720': u'1280x720',
            u'1080': u'1920x1080',
            u'4Kx2K': u'3840x2160',
        }
        fps_map = {
            u'60': u'60',
            u'5994': u'59',
            u'50': u'50',
            u'30': u'30',
            u'2997': u'29',
            u'25': u'25',
            u'24': u'24',
            u'2398': u'23',
        }
        res_dict = {}
        args = [u'getres']
        stdout, stderr = self.test_disp(args)
        res = stdout + u'\n' + stderr
        match = re.search(r'##ResID: \d+,.*? RES_(\w+) *= *(\d+)', res)
        if not match:
            self.logger.warning("test_disp getres fail: %r", res)
        res = match.group(1)
        for res_key, res_value in resolution_mapping.items():
            if res_key in res:
                res_dict[u'resolution'] = res_value
                break
        else:
            self.logger.warning("Invalid Resolution Found: %r", res)
            raise SynaInvalidOutputException
        res_dict[u'is_progress'] = u'I' not in res
        for res_key, res_value in fps_map.items():
            if res_key in res:
                res_dict[u'fps'] = res_value
                break
        else:
            self.logger.warning("Invalid FPS Found: %r", res)
            raise SynaInvalidOutputException
        return res_dict

    def test_disp_hdcp_state(self):
        '''Get HDMI HDCP State
        Output: hdcp_state - True/False (boolean)
                hdcp_version - 1/2 (str)
                hdcp_states (str list)
        '''
        hdcp14_enable = u'HDCP_STATE_AUTH_DONE'
        hdcp2x_enable = u'HDCP2X_TX_AUTH_DONE'
        hdcp14_re = re.compile(r'HDCP 1.4 state = (\w+)')
        hdcp2xmain_re = re.compile(r'Main state = (\w+)')
        hdcp2xsub_re = re.compile(r'Sub state = (\w+)')
        hdcp2xauth_re = re.compile(r'Auth state = (\w+)')
        hdcpfail_re = re.compile(r'(HDCP is in un authenticated State)')
        hdcp_states = set()
        hdcp_state = False
        hdcp_version = u'0'
        args = [u'hdcp', u'state']
        stdout, stderr = self.test_disp(args)
        res = stdout + u'\n' + stderr
        for pattern in (hdcp14_re, hdcp2xmain_re, hdcp2xsub_re, hdcp2xauth_re, hdcpfail_re):
            if not pattern.search(res):
                continue
            hdcp_states.add(pattern.search(res).group(1))
        if u'HDCP 2.2 state =' in res:
            hdcp_version = u'2'
            if hdcp2x_enable in hdcp_states:
                hdcp_state = True
        if u'HDCP 1.4 state =' in res:
            hdcp_version = u'1'
            if hdcp14_enable in hdcp_states:
                hdcp_state = True
        return hdcp_state, hdcp_version, hdcp_states

    def test_disp_getscale(self, plane):
        '''Get Plane Scaling State
        Input: str (main/pip/gfx0)
        Output: dict
        {
            'src': {'x': 0, 'y': 0, 'w': 1920, 'h': 1080},
            'dst': {'x': 0, 'y': 0, 'w': 3840, 'h': 2160},
        }
        '''
        pattern = re.compile(
            r'Src: x\[(?P<src_x>\d+)\], y\[(?P<src_y>\d+)\], w\[(?P<src_w>\d+)\], h\[(?P<src_h>\d+)\]\s*'
            r'Dst: x\[\](?P<dst_x>\d+), y\[(?P<dst_y>\d+)\], w\[(?P<dst_w>\d+)\], h\[(?P<dst_h>\d+)\]')
        plane2id = {
            'main': '0',
            'pip': '1',
            'gfx0': '2',
        }
        if plane not in plane2id:
            self.logger.warning("Invalid Plane(%s), should be %s", plane, '/'.join(plane2id.keys()))
            raise SynaInvalidOutputException
        args = [u'getscale', plane2id[plane]]
        stdout, stderr = self.test_disp(args)
        res = stdout + u'\n' + stderr
        match = pattern.search(res)
        if not match:
            self.logger.warning("Fail to get valid scale print")
            self.logger.debug(res)
            raise SynaInvalidOutputException
        ret = {
            'src': {
                'x': int(match.groupdict()['src_x']),
                'y': int(match.groupdict()['src_y']),
                'w': int(match.groupdict()['src_w']),
                'h': int(match.groupdict()['src_h']),
            },
            'dst': {
                'x': int(match.groupdict()['dst_x']),
                'y': int(match.groupdict()['dst_y']),
                'w': int(match.groupdict()['dst_w']),
                'h': int(match.groupdict()['dst_h']),
            },
        }
        return ret

    def ampclient_alpha_31_get(self):
        '''Get HDMI/SPDIF Passthrough Mode from AOUT
        Output: {
            'HDMI': {'UserSet': 'RAW', 'WorkFmt': 'PCM_MULTI'},
            'SPDIF': {'UserSet': 'RAW', 'WorkFmt': 'PCM_STERO'},
        }
        '''
        cmd = u'ampclient_alpha 31 -g'
        stdout, stderr = self.shell_auto(cmd, timeout=5)
        res = stdout + u'\n' + stderr
        path_re = re.compile(r'(?P<path>HDMI|SPDIF).*?UserSet\[ *(?P<UserSet>[^]]+)\].*?WorkFmt\[ *(?P<WorkFmt>[^]]+)\]')
        ret = {}
        for match in path_re.finditer(res):
            audio_path = match.groupdict().get(u'path')
            user_set = match.groupdict().get(u'UserSet')
            work_fmt = match.groupdict().get(u'WorkFmt')
            ret.update({audio_path: {u'UserSet': user_set, u'WorkFmt': work_fmt}})
        if not ret:
            self.logger.error("Fail to parser ampclient_alpha 31 -g")
            self.logger.error("Command output: %r", res)
        return ret

    def ampclient_alpha_15_fmt(self, port):
        '''Get HDMI/SPDIF Format by API AMP_SND_GetHDMIFormat/AMP_SND_GetSpdifFormat
        Input: port (str HDMI/SPDIF)
        Output: String (such as AMP_SND_HDMI_FORMAT_INVALID) / None (for API call fail)
        Detail return string refer:
            /synaptics-sdk/ampsdk/amp/inc/amp_sound_types.h
                AMP_SND_SPDIF_FORMAT
                AMP_SND_HDMI_FORMAT
        '''
        port2id = {
            'HDMI': '10',
            'SPDIF': '11',
        }
        if port not in port2id:
            self.logger.error('Invalid Port, only support %s', '/'.join(port2id.keys()))
            raise ValueError('Invalid Port')
        cmd = u'ampclient_alpha 15 -t ' + port2id[port]
        stdout, stderr = self.shell_auto(cmd, timeout=5)
        res = stdout + u'\n' + stderr
        format_re = re.compile(r'Format: (.*?) \(\d+\)')
        match = format_re.search(res)
        if not match:
            return None
        return match.group(1)

    def cpm_status(self):
        '''Get cpm status by cat /proc/cpm/status
        Output: {
            Modules1: Data1s
            Modules2: Data2s
        }
        Modules will be MOD/CORE/CLK SRC/CLK/PERIPHERAL/OTHERS
            MOD/CORE/CLK SRC/CLK/PERIPHERAL's Data format as below
                {
                    name1: values1
                    name2: values2
                }
                values will be dict, key list as below
                    en/cfg/startup(bool)
                    freq/ref/on/total(int)
                    status(string)
            OTHERS's Data format as dict, key as below
                leakage/temp/voltage(int)
                status(string)
        '''
        def filter_data(ret):
            int_data_keys = (
                u'total',
                u'on',
                u'freq',
                u'ref',
                )
            bool_data_map = {
                u'startup': (u'-', u'OFF'), # First for True
                u'cfg': (u'Y', u'N'),
                u'en': (u'ON', u'OFF'),
            }
            others_int_keys = (
                u'leakage',
                u'temp',
                u'voltage',
            )
            for module, values in ret.items():
                if module == u'OTHERS':
                    for int_data in others_int_keys:
                        if int_data in values:
                            values[int_data] = int(values[int_data])
                    continue
                for value in values.values():
                    for int_data in int_data_keys:
                        if int_data in value:
                            value[int_data] = int(value[int_data])
                    for bool_data, check_list in bool_data_map.items():
                        if bool_data in value:
                            assert value[bool_data] in check_list
                            value[bool_data] = value[bool_data] == check_list[0]

        cmd = u'cat /proc/cpm/status'
        stdout, stderr = self.shell(cmd, timeout=5)
        res = stdout + u'\n' + stderr

        ret = {}
        for module, pattern in CPM_PATTERNS.items():
            values = {}
            for match in pattern.finditer(res):
                matches = match.groupdict()
                name = matches.pop(u'name', None)
                if name:
                    values.update({name: matches})
                else:
                    values.update(matches)
            if values:
                ret.update({module: values})
        filter_data(ret)
        self.logger.info("cpm_status: %r", ret)
        return ret

    def get_linux_ext_storages(self, device=None):
        '''Get Synaptics Linux External Storages mount point list
        Input: device [SN(for USB device) / IP:Port(for network device)](str) / None(for self._device)]
        Output: Storage List
                Such as ['/mnt/media_rw/xxxx-yyyy', '/mnt/media_rw/aaaa-bbbb']
        '''
        self.connect_auto(device=device)
        mounts = self.get_partition_status(device=device)
        ext_devices = []
        for mount in mounts:
            mount_point = mount.get('mount_point', '')
            device_path = mount.get('device', '')
            if '/mnt/usb' not in mount_point or '/mnt/hdd' not in mount_point or '/mnt/sdcard' not in mount_point:
                continue
            ext_devices.append(mount_point)
        return ext_devices
