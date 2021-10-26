# -*- coding:utf-8 -*-
import clbfile
import rsa

ret = clbfile.make_clb_file('eicar.py')
pu = rsa.to_rsa_key('key.pkr')
k = clbfile.CLB('eicar.clb', pu)

module = clbfile.memory_loading('eicar', k.body)
print(dir(module))

kav = module.CLBMain()
kav.init('.')
print(kav.getinfo())
kav.uninit()