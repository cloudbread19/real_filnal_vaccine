# -*- coding:utf-8 -*-

# 엔지 및 모듈 테스트용 코드
import clb.engine

k2 = clb.engine.Engine(debug=True)
if k2.set_plugins('plugins') :
    kav = k2.create_engine_instance()
    if kav:
        print('success:Create')
        ret = kav.init() # 여기까지 잘 출력됨