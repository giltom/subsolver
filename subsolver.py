import math
import argparse
import contextlib
import enum
import string
import sys
import abc
import readline

PRINTABLE = set(string.printable) - {'\x0b', '\x0c'}

class Color(enum.Enum):
    ORIG = 93
    TRANS = 92

with open('words.txt', 'r') as f:
    WORDS = [l.strip().lower() for l in f]

FREQS = {
    'a' : {97: 0.07983659721025865, 98: 0.015263949560221991, 99: 0.02621265245863224, 100: 0.04226741725990764, 101: 0.1263508439548553, 102: 0.023771698117003227, 103: 0.019427849364159554, 104: 0.06216834223789161, 105: 0.06951947968898725, 106: 0.0014459848653599332, 107: 0.006761272188090216, 108: 0.03975178200895174, 109: 0.02510161724383835, 110: 0.06976290798232963, 111: 0.0763173855663371, 112: 0.017752087636410677, 113: 0.0010932841634927375, 114: 0.06008582273253808, 115: 0.06412453171362667, 116: 0.09216634637811191, 117: 0.028012633444928353, 118: 0.010089161865691195, 119: 0.0217989729978582, 120: 0.001720800400732555, 121: 0.018562387504284027, 122: 0.0006341914555011663},
    'n' : {33: 0.0006660480537718686, 34: 0.0046006319869994474, 35: 1.9316062373072943e-05, 36: 1.0379265407653457e-05, 37: 5.965095061869803e-07, 38: 2.6886310287954987e-05, 39: 0.0028015629315486434, 40: 0.0002881285523248251, 41: 0.00029000846107159623, 42: 0.00014673410810374035, 43: 1.1189072252416389e-05, 44: 0.01743700320044703, 45: 0.00401822179641325, 46: 0.010735558728094377, 47: 5.498733084305437e-05, 48: 0.0004630106787023341, 49: 0.0008944099687858867, 50: 0.0005578593053951924, 51: 0.00042348921251060035, 52: 0.0003821782178003057, 53: 0.0003806634451755036, 54: 0.0003613979957302283, 55: 0.00035542928545923014, 56: 0.00044300049617660727, 57: 0.0003091220717334784, 58: 0.0005177702513702989, 59: 0.0017585027938209611, 60: 3.4199878354720204e-06, 61: 2.8307087475418522e-05, 62: 3.7887391665694266e-06, 63: 0.0007325895929893083, 64: 2.1185125492458816e-06, 65: 0.0023412781205291275, 66: 0.0014067646368818335, 67: 0.001485120679530904, 68: 0.0009464834410714459, 69: 0.0014019094110223843, 70: 0.0008641217467081017, 71: 0.0009180859733678172, 72: 0.0017258936074827395, 73: 0.004242465988230014, 74: 0.0004695469768064921, 75: 0.00031211908010092695, 76: 0.0010231837179397064, 77: 0.0016504767298550632, 78: 0.0010947612434730155, 79: 0.0010903796100093877, 80: 0.0010260180418963766, 81: 8.7018083720731e-05, 82: 0.0010626184191123583, 83: 0.002100320816911743, 84: 0.003144704121180422, 85: 0.0003031895135537643, 86: 0.00035935540257267897, 87: 0.0012594990930362175, 88: 0.00011844871188309226, 89: 0.00047781857529228486, 90: 3.2515190900883036e-05, 91: 0.00024975310742679605, 92: 8.821110273310497e-07, 93: 0.00025773187397318796, 94: 2.0064410662652976e-06, 95: 0.0017758738736829518, 96: 4.555163501791486e-07, 97: 0.07341246107852295, 98: 0.013076583783984515, 99: 0.023387011994623997, 100: 0.03915937046064174, 101: 0.11848732954700189, 102: 0.02169188743203312, 103: 0.017516219662868662, 104: 0.05726314837189545, 105: 0.06172177494433111, 106: 0.000902489961187874, 107: 0.006103380426240459, 108: 0.036695684974233915, 109: 0.022167439271201895, 110: 0.06510045901551109, 111: 0.07132412106466275, 112: 0.01581822462422983, 113: 0.0009503553300479686, 114: 0.05595040447881607, 115: 0.05874487075484565, 116: 0.08430823864477002, 117: 0.026276872793924825, 118: 0.009213844901765748, 119: 0.019424670485708517, 120: 0.001514349645334066, 121: 0.017135285077008528, 122: 0.0005692435989405428, 123: 8.835571109824121e-06, 124: 9.780586775989434e-05, 125: 8.918720919777458e-06, 126: 1.3607647159319964e-05},
    'p' : {9: 5.5407260740153e-07, 10: 0.0029071983406727866, 13: 0.0, 32: 0.18187115925083855, 33: 0.0005429764192798983, 34: 0.003750532215474558, 35: 1.5746861390140292e-05, 36: 8.461396041754215e-06, 37: 4.862871288364492e-07, 38: 2.1918287134282865e-05, 39: 0.002283893182098547, 40: 0.00023488847200688585, 41: 0.00023642101326140072, 42: 0.00011962073930432606, 43: 9.1215676590837e-06, 44: 0.014215012726384674, 45: 0.00327573914604697, 46: 0.008751853870210867, 47: 4.4826831694559957e-05, 48: 0.0003774560694028519, 49: 0.0007291418681720921, 50: 0.00045477867008256753, 51: 0.00034523733672139694, 52: 0.00031155974265343266, 53: 0.0003103248680656601, 54: 0.0002946192674016029, 55: 0.0002897534489185182, 56: 0.0003611433466264292, 57: 0.00025200283174720863, 58: 0.0004220972278300379, 59: 0.0014335685614204118, 60: 2.7880462053289753e-06, 61: 2.3076534659329682e-05, 62: 3.0886600667915078e-06, 63: 0.0005972224853002842, 64: 1.72705610604945e-06, 65: 0.0019086592975147418, 66: 0.0011468241983112392, 67: 0.001210701696677307, 68: 0.0007715932609221541, 69: 0.0011428661158019826, 70: 0.0007044502708060815, 71: 0.0007484430463948189, 72: 0.0014069848650440193, 73: 0.0034585477401528324, 74: 0.00038278459745701127, 75: 0.00025444605617027174, 76: 0.0008341209441063607, 77: 0.001345503435985491, 78: 0.0008924724523720145, 79: 0.0008889004523711067, 80: 0.0008364315447670139, 81: 7.093897691571716e-05, 82: 0.0008662689441145304, 83: 0.0017122258222172983, 84: 0.0025636291161630345, 85: 0.00024716648521132614, 86: 0.0002929541023846781, 87: 0.0010267702213830406, 88: 9.656188781331771e-05, 89: 0.0003895277789768767, 90: 2.6507069313666815e-05, 91: 0.00020360400005174094, 92: 7.191155117339007e-07, 93: 0.0002101084587992685, 94: 1.635693069722602e-06, 95: 0.0014477298320510733, 96: 3.7134653474783393e-07, 97: 0.05984738641784901, 98: 0.010660306864095194, 99: 0.019065585371181682, 100: 0.03192354460547232, 101: 0.09659336974731911, 102: 0.017683684080401465, 103: 0.014279591657094153, 104: 0.046682126137275654, 105: 0.050316892544139936, 106: 0.0007357288483717859, 107: 0.004975604433607662, 108: 0.029915096241925617, 109: 0.01807136396828876, 110: 0.053071267049790385, 111: 0.05814492759893452, 112: 0.012895350293706078, 113: 0.0007747497064675106, 114: 0.0456119496320532, 115: 0.04789005747091595, 116: 0.06872985406367062, 117: 0.021421460837126906, 118: 0.007511320668575484, 119: 0.01583540101392517, 120: 0.001234529765990293, 121: 0.013969045749424477, 122: 0.00046405938625654314, 123: 7.20294389621989e-06, 124: 7.973340596085634e-05, 125: 7.2707293747849706e-06, 126: 1.1093240926911483e-05}
}
    

@contextlib.contextmanager
def print_color(color):
    print('\033[{:d}m'.format(color.value), end='')
    try:
        yield
    finally:
        print('\033[0m', end='')

class SubData(abc.ABC):
    def __init__(self, data):
        self.data = data
        self.counts = {}
        for val in data:
            self.counts[val] = self.counts.get(val, 0) + 1
        self.trans = {}
        self.freqs = {val : self.counts[val] / len(data) for val in self.counts}
    
    def values(self):
        return sorted(self.counts)
    
    def translated_values(self):
        return (val for val in self.values() if self.is_translated(val))
    
    def values_by_freq(self):
        return sorted(self.counts, key=lambda v: self.counts[v])
    
    def data_length(self):
        return len(self.data)
    
    def translate(self, value):
        return self.trans.get(value, value)
    
    def translation(self, value):
        return self.trans.get(value)
    
    def is_translated(self, value):
        return value in self.trans
    
    def count(self, value):
        return self.counts.get(value, 0)
    
    def tcount(self, value):
        return sum(count for val, count in self.counts.items() if self.trans[val] == value)
    
    @classmethod
    @abc.abstractmethod
    def empty_data(cls):
        return ''

    @classmethod
    @abc.abstractmethod
    def append_to_data(cls, data, value):
        return data + value
    
    def tdata(self):
        res = self.empty_data()
        for val in self.data:
            res = self.append_to_data(res, self.translate(val))
        return res
    
    def freq(self, value):
        return self.freqs.get(value, 0)
    
    def tfreq(self, value):
        return math.fsum(freq for val, freq in self.freqs.items() if self.trans[val] == value)
    
    def val_in_orig(self, value):
        return value in self.counts

    def add_translation(self, fromval, toval):
        self.trans[fromval] = toval
    
    def remove_translation(self, value):
        del self.trans[value]
    
    @classmethod
    @abc.abstractmethod
    def val_to_string(cls, value):
        pass
    
    @classmethod
    @abc.abstractmethod
    def string_to_val(cls, s):
        pass
    
    def print_value(self, value, end=''):
        if value in self.trans:
            color = Color.TRANS
        else:
            color = Color.ORIG
        with print_color(color):
            print(self.val_to_string(self.translate(value)), end='')
    
    def print_translation(self, start=0, stop=None):
        if stop is None:
            stop = len(self.data)
        for i in range(start, min(len(data), stop)):
            val = self.data[i]
            if self.is_translated(val):
                color = Color.TRANS
            else:
                color = Color.ORIG
            with print_color(color):
                self.print_value(val)
        print()
    
    def print_translation_map(self, values=None):
        if values is None:
            values = self.values()
        for val in values:
            with print_color(Color.ORIG):
                print(self.val_to_string(val), end='')
            if self.is_translated(val):
                print(' => ', end='')
                with print_color(Color.TRANS):
                    print(self.val_to_string(self.translate(val)), end='')
            print()
    
    def tvalues(self):
        return sorted(set(self.tdata()))
    
    def print_freqs(self, sort_by_freq=True, freqs=None):
        if sort_by_freq:
            sort_ind = 1
            reverse = True
        else:
            sort_ind = 0
            reverse = False
        if freqs is None:
            freqs = self.freqs
        sfreqs = sorted(freqs.items(), key=lambda t: t[sort_ind], reverse=reverse)
        for val, freq in sfreqs:
            with print_color(Color.ORIG):
                print(self.val_to_string(val), end='')
            if self.is_translated(val):
                print(' => ', end='')
                self.print_value(val)
            print(' : {:.02%}'.format(freq))

class CharSubData(SubData):
    ESCAPED = {
        'n' : '\n',
        'r' : '\r',
        't' : '\t',
        's' : ' ',
        '\\' : '\\'
    }

    @classmethod
    def val_to_string(cls, value):
        if type(value) is int:
            value = chr(value)
        if value == '\n':
            return '\\n'
        if value == '\r':
            return '\\r'
        if value == '\t':
            return '\\t'
        if value == '\\':
            return '\\\\'
        return value
    
    @classmethod
    def string_to_val(cls, s):
        MESSAGE = 'Invalid character.'
        if len(s) == 0:
            raise CommandError(MESSAGE)
        if len(s) == 1:
            return s
        if len(s) != 2 or s[0] != '\\' or s[1] not in cls.ESCAPED:
            raise CommandError(MESSAGE)
        return cls.ESCAPED[s[1]]

    @classmethod
    def empty_data(cls):
        return ''
    
    @classmethod
    def append_to_data(cls, data, value):
        return data + value

class BinarySubData(SubData):
    @classmethod
    def val_to_string(cls, value):
        c = chr(value)
        if c in PRINTABLE:
            return CharSubData.val_to_string(c)
        return '\\x{:02x}'.format(value)
    
    @classmethod
    def string_to_val(cls, s):
        if len(s) == 4 and s.startswith('\\x'):
            try:
                return int(s[2:4], 16)
            except ValueError:
                raise CommandError('Invalid hex escape.')
        return ord(CharSubData.string_to_val(s))
    
    @classmethod
    def empty_data(cls):
        return b''
    
    @classmethod
    def append_to_data(cls, data, value):
        return data + bytes([value])

def s_if_not_1(num):
    if num != 1:
        return 's'
    return ''

class CommandError(Exception):
    pass

class QuitError(Exception):
    pass

class SpecialAction(abc.ABC):
    @abc.abstractmethod
    def is_applicable(self, cmdline, inpline):
        pass
    
    @abc.abstractmethod
    def execute(self, cmdline, inpline):
        pass

class Command:
    def __init__(self, name, func=None, nargs=None, min_args=None, max_args=None, invocation=None, helptext=None):
        if nargs is not None and (min_args is not None or max_args is not None):
            raise ValueError('If nargs is given, min_args and max_args should not be given.')
        self.name = name
        self.helptext = helptext
        self.func = func
        self.nargs = nargs
        self.min_args = min_args
        self.max_args = max_args
        self.invocation = invocation
    
    def execute(self, cmdline, args):
        if not self.nargs_ok(len(args)):
            raise CommandError(self.get_usage_text())
        if self.func is not None:
            self.func(cmdline, *args)
    
    def get_usage_text(self):
        if self.invocation is not None:
            return f'Usage: {self.name} {self.invocation}'
        if self.nargs is not None:
            return f'Expected {self.nargs} argument{s_if_not_1(self.nargs)}.'
        if self.min_args is not None:
            if self.max_args is None:
                return f'Expected at least {self.min_args} argument{s_if_not_1(self.min_args)}.'
            else:
                return f'Expected {self.min_args} to {self.max_args} arguments.'
        if self.max_args is not None:
            return f'Expected at most {self.max_args} argument{s_if_not_1(self.max_args)}.'
        raise ValueError('No limitation on arguments.')
    
    def nargs_ok(self, nargs):
        if self.nargs is not None and nargs != self.nargs:
            return False
        if self.min_args is not None and nargs < self.min_args:
            return False
        if self.max_args is not None and nargs > self.max_args:
            return False
        return True

class HelpCommand(Command):
    def __init__(self, name):
        helptext = 'Get help for a command or a list of all commands.'
        invocation = '<?command>'
        super().__init__(name, max_args=1, helptext=helptext, invocation=invocation)
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        if len(args) == 0:
            print('Available commands:')
            print(', '.join(cmd.name for cmd in cmdline.commands))
            print('Type "help <command>" for command-specific help.')
        else:
            command = cmdline.lookup_command(args[0])
            if command.invocation is not None:
                print(f'Usage: {command.name} {command.invocation}')
            if command.helptext is not None:
                print(command.helptext)

class QuitCommand(Command):
    def __init__(self, name):
        helptext = 'Quit the program.'
        super().__init__(name, nargs=0, helptext=helptext)
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        raise QuitError()

class CommandLine:
    def __init__(self, prompt='>', default_action=None, add_help=True, add_quit=True):
        self.prompt = prompt
        self.default_action = default_action
        self.commands = []
        if add_help:
            self.commands.append(HelpCommand('help'))
        if add_quit:
            self.commands.append(QuitCommand('quit'))
        self.specials = []
    
    def no_command(self):
        if self.default_action is not None:
            self.default_action()
    
    def add_command(self, command):
        self.commands.append(command)
    
    def add_special(self, special):
        self.specials.append(special)
    
    def lookup_command(self, cmdname):
        matches = []
        for command in self.commands:
            if command.name.startswith(cmdname):
                matches.append(command)
        if len(matches) == 0:
            raise CommandError('Unrecognized command ' + cmdname)
        if len(matches) > 1:
            matchnames = ', '.join(command.name for command in matches)
            raise CommandError('Ambiguous command {}, could mean {}'.format(cmdname, matchnames))
        return matches[0]
    
    def execute_command(self, cmdname, arguments):
        command = self.lookup_command(cmdname)
        command.execute(self, arguments)
    
    def execute_line(self, inline):
        inline = inline.strip()
        if inline == '':
            self.no_command()
            return
        for special in self.specials:
            if special.is_applicable(self, inline):
                special.execute(self, inline)
                return
        args = inline.split()
        cmdname = args[0]
        args = args[1:]
        self.execute_command(cmdname, args)
    
    def main_loop(self):
        try:
            while True:
                inline = input(self.prompt)
                try:
                    self.execute_line(inline)
                except CommandError as e:
                    print('Error:', str(e))
        except (EOFError, KeyboardInterrupt):
            print()
        except QuitError:
            pass

class FreqCommand(Command):
    def __init__(self):
        invocation = "[-s]"
        helptext = "Calculate frequencies for the data. If -s is given, sort by the characters, not by the frequencies."
        super().__init__('freq', max_args=1, invocation=invocation, helptext=helptext)
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        if len(args) == 0:
            cmdline.sdata.print_freqs()
        else:
            if args[0] != '-s':
                raise CommandError('Invalid argument', args[0])
            cmdline.sdata.print_freqs(sort_by_freq=False)

class SetCommand(Command):
    def __init__(self):
        invocation = '<character> <substitute> <character> <substitute> ...'
        helptext = "Set the substitutions for characters."
        super().__init__('set', min_args=2, invocation=invocation, helptext=helptext)
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        if len(args) % 2 != 0:
            raise CommandError('Number of arguments must be even.')
        changes = []
        for i in range(0, len(args), 2):
            fromval = cmdline.string_to_val_from(args[i])
            toval = cmdline.string_to_val(args[i+1])
            changes.append((fromval, toval))
        for fromval, toval in changes:
            cmdline.sdata.add_translation(fromval, toval)

class ResetCommand(Command):
    def __init__(self):
        invocation = '<character>'
        helptext = 'Remove the substitution for a character.'
        super().__init__('reset', nargs=1, invocation=invocation, helptext=helptext)
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        val = cmdline.string_to_val_from(args[0], check_translated=True)
        cmdline.sdata.remove_translation(val)

class MapCommand(Command):
    def __init__(self):
        invocation = '<?character> <?character> ...'
        helptext = 'Print the substitutions for the given characters or for all characters. map set displays all characters that have substitutions.'
        super().__init__('map', invocation=invocation, helptext=helptext)
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        if len(args) == 1 and args[0] == 'set':
            vals = list(cmdline.sdata.translated_values())
        else:
            vals = [cmdline.string_to_val_from(arg) for arg in args]
        if len(vals) == 0:
            vals = None
        cmdline.sdata.print_translation_map(vals)

class PrintCommand(Command):
    def __init__(self):
        invocation = '<?amount> <?start>'
        helptext = 'Print the substituted data. amount is the amount to print (default: everything), start is the index to start from (defaut: 0).'
        super().__init__('print', max_args=2, invocation=invocation, helptext=helptext)
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        try:
            amount = None
            start = 0
            if len(args) >= 1:
                amount = int(args[0])
            if len(args) == 2:
                start = int(args[1])
            if (amount is not None and amount < 0) or start < 0:
                raise ValueError()
        except ValueError:
            raise CommandError('Arguments must be non-negative integers.')
        if amount is None:
            stop = None
        else:
            stop = start + amount
        cmdline.sdata.print_translation(start, stop)

class EFreqCommand(Command):
    def __init__(self):
        invocation = '<?table> [-s]'
        helptext = (
            'Print an expected English frequency distribution for the given table, '
            'which can be alpha (lowercase letters, default), '
            'nospace (all printable ASCII characters except whitespace), '
            'or prinable (all printable ASCII characters). '
            'You can give a prefix of a table name (i.e. a, n, or p). '
            'If -s is given, orders the output by the characters (not the frequencies).'
        )
        super().__init__('efreq', max_args=2, invocation=invocation, helptext=helptext)
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        if '-s' in args:
            sort_by_freq = False
            args.remove('-s')
        else:
            sort_by_freq = True
            if len(args) == 2:
                raise CommandError('Invalid argument.')
        if len(args) == 0:
            table = 'a'
        else:
            table = args[0][0]
            if table not in FREQS:
                raise CommandError('Invalid table name.')
            cmdline.sdata.print_freqs(sort_by_freq=sort_by_freq, freqs=FREQS[table])

class WriteCommand(Command):
    def __init__(self):
        invocation = '<filename>'
        helptext = 'Write the translated data to a file.'
        super().__init__('write', nargs=1, invocation=invocation, helptext=helptext)

    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        if cmdline.is_binary():
            mode = 'wb'
        else:
            mode = 'w'
        try:
            with open(args[0], mode, encoding=cmdline.encoding) as f:
                f.write(cmdline.sdata.tdata())
        except IOError as e:
            raise CommandError('Could not write file: ' + str(e))

class ExportMapCommand(Command):
    def __init__(self):
        helptext = 'Export and print the current substitution map in a format that can be read by set.'
        super().__init__('exportmap', nargs=0, helptext=helptext)
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        parts = []
        for val in cmdline.sdata.translated_values():
            fromval = cmdline.sdata.val_to_string(val)
            if fromval == ' ':
                fromval = '\\s'
            toval = cmdline.sdata.val_to_string(cmdline.sdata.translate(val))
            if toval == ' ':
                toval = '\\s'
            parts.append(fromval)
            parts.append(toval)
        print(' '.join(parts))

class WordsCommand(Command):
    MAX_MATCHES = 100

    def __init__(self):
        helptext = 'Search an English word list for words matching a pattern. ? signifies any character.'
        invocation = '<pattern>'
        super().__init__('words', nargs=1, invocation=invocation, helptext=helptext)
    
    @classmethod
    def pattern_matches(cls, word, pattern):
        if len(word) != len(pattern):
            return False
        return all(cp == '?' or cp == cw for cw, cp in zip(word, pattern))
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        pattern = args[0].lower()
        matches = []
        for word in WORDS:
            if self.pattern_matches(word, pattern):
                matches.append(word)
        if len(matches) == 0:
            print('No matches found.')
        else:
            print(', '.join(matches[:self.MAX_MATCHES]))
            if len(matches) > self.MAX_MATCHES:
                print(len(matches)  - self.MAX_MATCHES, 'additional matches found.')

class FindCommand(Command):
    CONTEXT_SIZE = 100

    def __init__(self):
        helptext = 'Find the first index of a character in the substituted data.'
        invocation = '<character>'
        super().__init__('find', nargs=1, invocation=invocation, helptext=helptext)
    
    def execute(self, cmdline, args):
        super().execute(cmdline, args)
        data = cmdline.sdata.tdata()
        value = cmdline.string_to_val(args[0])
        try:
            ind = data.index(value)
            print(f'Character found at index {ind}:')
            cmdline.sdata.print_translation(ind, ind + self.CONTEXT_SIZE)
        except ValueError:
            print('Character not found in substituted data.')

class SubsolveCommandLine(CommandLine):
    def __init__(self, sdata, encoding):
        super().__init__()
        self.sdata = sdata
        self.encoding = encoding
        self.add_command(FreqCommand())
        self.add_command(SetCommand())
        self.add_command(ResetCommand())
        self.add_command(MapCommand())
        self.add_command(PrintCommand())
        self.add_command(EFreqCommand())
        self.add_command(WriteCommand())
        self.add_command(ExportMapCommand())
        self.add_command(WordsCommand())
        self.add_command(FindCommand())
    
    def is_binary(self):
        return isinstance(self.sdata, BinarySubData)
    
    def string_to_val(self, value):
        return self.sdata.string_to_val(value)
    
    def string_to_val_from(self, value, check_translated=False):
        value = self.string_to_val(value)
        if not self.sdata.val_in_orig(value):
            raise CommandError('Character not in the data.')
        if check_translated and not self.sdata.is_translated(value):
            raise CommandError('No substitution for the given character.')
        return value

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Frequency analysis helper.')
    parser.add_argument('infile', help='File to read.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--binary', action='store_true', help='Binary mode: work on bytes.')
    group.add_argument('-e', '--encoding', default='utf8', help='The encoding to use for text mode.')
    args = parser.parse_args()
    if args.binary:
        encoding = None
        mode = 'rb'
    else:
        encoding = args.encoding
        mode = 'r'
    try:
        with open(args.infile, mode, encoding=encoding) as f:
            data = f.read()
    except LookupError:
        print('Unknown encoding', args.encoding)
        sys.exit(1)
    except FileNotFoundError:
        print('File', args.infile, 'not found.')
        sys.exit(1)
    except IOError:
        print('Could not read file', args.infile)
        sys.exit(1)
    if args.binary:
        sdata = BinarySubData(data)
    else:
        sdata = CharSubData(data)
    cmdline = SubsolveCommandLine(sdata, encoding)
    cmdline.main_loop()