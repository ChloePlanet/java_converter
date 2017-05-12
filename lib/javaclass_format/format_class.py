#!/usr/bin/env python3

import sys
import readclass
import copy
import struct

def _args_count(desc):
    '''Get arguments count from method signature string
    e.g. ()V - 0; (II)V - 2 (two int params)
    '''
    '''Recursive parsing for method signuture'''
    if len(desc) == 0:
        return 0
    char_ = desc[0]
    if char_ == "(":
        return _args_count(desc[1:])
    if char_ == ")":
        return 0
    if char_ in ["B", "C", "F", "I", "S", "Z"]:
        return 1 + _args_count(desc[1:])
    if char_ in ["J", "D"]:
        return 2 + _args_count(desc[1:])
    if char_ == "L":
        return 1 + _args_count(desc[desc.index(";") + 1:])
    if char_ == "[":
        return _args_count(desc[1:])
    raise Exception("Unknown type def %s", str(char_))

def _varint(i):
    if i < 128:
        return bytes([i])
    elif i < 16384:
        bh = int(i / 128)
        bl = i % 128 + 128
        return bytes([bl, bh])
    else:
        raise(Exception("Out of range. %d" % i))

class MethodMini():

    def __init__(self):
        self.code = None
        self.method_id = None

    def __str__(self):
        return "CP_Idx: %d, code: %s" % (self.method_id, str(self.code))

    def save(self, f, is_last=False):
        assert self.method_id < 128
        assert self.code.max_stack < 256
        assert self.code.max_locals < 256
        assert self.code.code_length < 16384
        f.write(struct.pack(">B", self.method_id + (128 if is_last else 0) ))
        f.write(struct.pack(">B", self.code.max_stack))
        f.write(struct.pack(">B", self.code.max_locals))
        f.write(_varint(self.code.code_length))
        f.write(bytes(self.code.code))

class ConstantMini():

    # contains: class name, i.e. int[][] -> [[I
    #CONST_CLASS = 7

    # method contains: class name, method name, signiture
    CONST_METHOD = 10

    CONST_INTEGER = 3
    #CONST_FLOAT = 4
    CONST_STRING = 8
    
    CONST_NONE = 0

    def __init__(self):
        self.type = 0xFF

    def set_string(self, str):
        self.type = self.CONST_STRING
        self.value = str
    
    def set_method(self, class_name, name, signature):
        self.type = self.CONST_METHOD
        self.class_name = class_name
        self.name = name
        self.signature = signature
        self.nargs = _args_count(signature)
    
    def set_int(self, v):
        self.type = self.CONST_INTEGER
        self.value = v

    def __str__(self):
        if self.type == self.CONST_INTEGER:
            return "Const Int: %d" % self.value
        elif self.type == self.CONST_METHOD:
            return "Const Method: (%s/%s %s nargs=%d)" % (
                self.class_name if self.class_name != "" else "THIS", 
                self.name if self.name != "" else "MAIN", 
                self.signature, self.nargs)
        elif self.type == self.CONST_STRING:
            return "Const String: \"%s\"" % self.value
    
    def save(self, f, is_last=False):
        f.write(struct.pack(">B", self.type + (128 if is_last else 0) ))
        if self.type == self.CONST_INTEGER:
            f.write(struct.pack(">B", 4))
            f.write(struct.pack(">i",self.value))
        elif self.type == self.CONST_METHOD:
            if len(self.class_name) == 0:
                name = ""
            else:
                name = self.name

            total_len = 1 + len(self.class_name) + 1 + len(name) + 1
            assert total_len < 256
            assert self.nargs < 256
            f.write(struct.pack(">B", total_len))
            f.write(struct.pack(">B", len(self.class_name)))
            f.write(self.class_name.encode("ascii"))
            f.write(struct.pack(">B", len(name)))
            f.write(name.encode("ascii"))
            f.write(struct.pack(">B", self.nargs))
        elif self.type == self.CONST_STRING:
            f.write(struct.pack(">B", len(self.value)))
            f.write(self.value.encode("ascii"))
        elif self.type == self.CONST_NONE:
            f.write(b'\00')
        else:
            raise(Exception("EE: Constant not set."))

class JavaClassMini():

    ACC_PUBLIC = 0x0001
    ACC_STATIC = 0x0008
    OPCODES_SUPPORT = ["nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3", "iconst_4", "iconst_5", "bipush", "sipush", "ldc", "iload", "aload", "iload_0", "iload_1", "iload_2", "iload_3", "aload_0", "aload_1", "aload_2", "aload_3", "iaload", "aaload", "baload", "caload", "saload", "istore", "astore", "istore_0", "istore_1", "istore_2", "istore_3", "astore_0", "astore_1", "astore_2", "astore_3", "iastore", "aastore", "bastore", "castore", "sastore", "pop", "pop2", "dup", "dup_x1", "dup_x2", "swap", "iadd", "isub", "imul", "idiv", "irem", "ineg", "ishl", "ishr", "iushr", "iand", "ior", "ixor", "iinc", "i2b", "i2c", "i2s", "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle", "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple", "if_acmpeq", "if_acmpne", "goto", "ireturn", "areturn", "return", "invokestatic", "invokevirtual", "newarray", "arraylength", "ifnull", "ifnonnull"]

    def __init__(self, jc):
        self.jc = jc
        self.methods = []
        self.constant_pool = []

    def find_method_by_name(self, name, signature):
        for m in self.jc.methods:
            # only process public static functions
            want_flags = (self.ACC_PUBLIC | self.ACC_STATIC)
            if m.access_flags & want_flags != want_flags: continue

            _name_index = m.name_index
            _sign_index = m.descriptor_index
            _name = self.jc.get_cpi(_name_index).value
            _sign = self.jc.get_cpi(_sign_index).value
            if _name == name and _sign == signature:
                return m
        return None

    def add_constant(self, constant):
        if 'jcm_id' in dir(constant):
            # processed before
            return constant.jcm_id

        cm = self.build_constant(constant)
        if not cm:
            raise(Exception("EE: Constant not supported by JCMini."))

        self.constant_pool.append(cm)
        constant.jcm_id = len(self.constant_pool) - 1
        return constant.jcm_id

    def build_constant(self, constant):
        cm = ConstantMini()
        if type(constant) == readclass.CPIInt:
            cm.set_int(constant.value)
            print("II: add int %d to CP" % (constant.value))
        elif type(constant) == readclass.CPIStringReference:
            str_idx = constant.string_index
            str = self.jc.get_cpi(str_idx).value
            cm.set_string(str)
            print("II: add string \"%s\" to CP" % str)
        elif type(constant) == readclass.CPIMethodReference:
            class_idx = constant.class_index
            class_name_idx = self.jc.get_cpi(class_idx).name_index
            class_name = self.jc.get_cpi(class_name_idx).value
            if class_idx == self.jc.this_class:
                class_name = ''
            name_n_type_idx = constant.name_and_type_index
            name_idx = self.jc.get_cpi(name_n_type_idx).name_index
            desc_idx = self.jc.get_cpi(name_n_type_idx).descriptor_index
            method_name = self.jc.get_cpi(name_idx).value
            method_signature = self.jc.get_cpi(desc_idx).value
            cm.set_method(class_name, method_name, method_signature)
            print("II: add method %s/%s %s to CP" % (class_name if class_name != '' else 'THIS', method_name, method_signature))
        else:
            return None
        return cm

    def add_method(self, method, constant_pool_id = None):
        if 'jcm_id' in dir(method):
            # processed before
            return method.jcm_id

        # Process the method
        mm = MethodMini()
        for attr in method.attributes:
            if type(attr) == readclass.AttributeCode:
                # Found code attribute
                mm.code = copy.deepcopy(attr)
                break
        if not mm.code:
            raise(Exception("EE: No code attr in method."))
            return []
        
        if constant_pool_id != None:
            mm.method_id = constant_pool_id
        
        # iterate all code to find constant_pool references
        # and check if op is supported
        for code in mm.code.opcodes:
            if code[1] not in self.OPCODES_SUPPORT:
                raise(Exception("EE: Opcode %s not supported. " % code))
                return []
            if code[1] == 'ldc':
                const_id_new = self.add_constant(self.jc.get_cpi(code[2][0]))
                mm.code.code[code[0] + 1] = const_id_new
            elif code[1] == 'invokestatic':
                const_id_new = self.add_constant(self.jc.get_cpi((code[2][0]<<8) + code[2][1]))
                mm.code.code[code[0] + 1] = 0
                mm.code.code[code[0] + 2] = const_id_new
                subcm = self.constant_pool[const_id_new]
                if subcm.class_name == '':
                    subm = self.find_method_by_name(subcm.name, subcm.signature)
                    if not subm:
                        raise(Exception("EE: method %s not found." % subcm.name))
                        return None
                    print("II: begin process method %s/%s %s" % ('THIS', subcm.name, subcm.signature))
                    self.add_method(subm, const_id_new)
                    print("II: end process method %s/%s" % ('THIS', subcm.name))
            elif code[1] == 'invokevirtual':
                # we only support String.getBytes()
                cm = self.build_constant(self.jc.get_cpi((code[2][0]<<8) + code[2][1]))
                if cm.class_name == "java/lang/String" and cm.name == "getBytes" and cm.signature == "()[B":
                    pass
                else:
                    raise(Exception("EE: method %s.%s not supported." % (cm.class_name, cm.name)))

        self.methods.append(mm)
        method.jcm_id = len(self.methods) - 1
        return method.jcm_id

    def from_javaclass(self):
        mlist = []
        main_method = self.find_method_by_name("_main", "()I")
        main_method = self.find_method_by_name("_main", "()V") if not main_method else main_method

        if not main_method:
            raise(Exception("EE: No main method in class."))
            return

        # Add method ref to constant pool
        cm = ConstantMini()
        cm.set_method("", "", "")
        method_id = len(self.constant_pool)
        print("II: add method %s/%s to CP" % ("THIS", "MAIN"))
        self.constant_pool.append(cm)
        print("II: begin process method %s/%s" % ("THIS", "MAIN"))
        self.add_method(main_method, len(self.constant_pool) - 1)
        print("II: end process method %s/%s" % ("THIS", "MAIN"))

    def __str__(self):
        s = ["JavaClassMini"]
        s.append("  Constants:")
        for i, cm in enumerate(self.constant_pool):
            s.append("    %d> %s" % (i, str(cm)))
        
        s.append("  Methods:")
        for i, mm in enumerate(self.methods):
            s.append("    %d> %s" % (i, str(mm)))
        
        return "\r\n".join(s)

    def save(self, fn):
        assert len(self.constant_pool) < 128
        assert len(self.methods) < 128
        
        f = open(fn, "wb")
        f.write(b'\xCA')
        #f.write(struct.pack(">B", len(self.constant_pool)))

        if len(self.constant_pool) == 1:
            cm = ConstantMini()
            cm.type = cm.CONST_NONE
            self.constant_pool.append(cm)

        for i, cm in enumerate(self.constant_pool):
            if i == 0:
                if cm.type == cm.CONST_METHOD and cm.class_name == "" and cm.name == "" and cm.signature == "":
                    # id 0 should be THIS/MAIN, ignore, do not write to file
                    pass
                else:
                    raise(Exception("CP #0 should be THIS/MAIN. %s" % str(cm)))
            else:
                cm.save(f, i==len(self.constant_pool)-1)
        #f.write(struct.pack(">B", len(self.methods)))
        for i, mm in enumerate(self.methods):
            mm.save(f, i==len(self.methods)-1)

if __name__=="__main__":
    if len(sys.argv) < 2:
        print("%s class_file" % sys.argv[0])
    else:
        fn = sys.argv[1]
        f = open(fn, "rb")
        jc = readclass.JavaClass(f.read())
        jc.decode()

        jcm = JavaClassMini(jc)
        jcm.from_javaclass()
        print(str(jcm))

        jcm.save(fn + ".min")
