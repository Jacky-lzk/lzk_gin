#!/usr/bin/env python
# -*- coding:utf-8 -*-
import shutil
import tornado.web
import logging
import comFuncs
import globalM
import datetime
import json
import time
import os
import base64
import hmac
import dbMng
import uuid
import urllib.request
import workThreads
import detect
import recog
import redisMng
import requests
import urllib.parse
import time
from hashlib import sha1
from infoParse import InfoParse
from outerInfoParse import info_parse
from tornado.concurrent import run_on_executor

__all__ = [ 'check_paras', 'getImgPath', 'FindCardHandler', 'UploadFileHandler', 'PolicyHandler', 'PolicyRcgHandler',
            'UpdateRcgHandler', 'ModTemplateHandler', 'GetTemplatesHandler', 'GetServerTS']

def check_paras(region, userId, timestamp, random, signature):

    if len(region) <= 0:
        return False, "region is empty"

    if len(userId) <= 0:
        return False, "userId is empty"

    if len(timestamp) <= 0:
        return False, "timestamp is empty"

    if len(random) <= 0:
        return False, "random is empty"

    if len(signature) <= 0:
        return False, "signature is empty"

    localTs = time.time()
    if abs(localTs - int(timestamp)) > 30000.0:
        return False, "timestamp is invalid."

    redisCon = redisMng.getRedisCon()
    if redisCon is None:
        return False, "redisCon is None."

    redisRandom = redisCon.hget(redisMng.G_REDIS_USER_KEY + userId, redisMng.G_USER_FIELD_RANDOM)
    if redisRandom == random:
        return False, "random cannot repeat"

    redisCon.hset(redisMng.G_REDIS_USER_KEY + userId, redisMng.G_USER_FIELD_RANDOM, random)

    with dbMng.getDbCurson() as myCur:
        sql = "SELECT Region, SecretKey FROM tbl_customer WHERE UserId = '%s' LIMIT 1 " % userId
        myCur.execute(sql)
        oneRec = myCur.fetchone()
        if oneRec is None or len(oneRec) < 2:
            logging.info("oneRec is null or len(oneRec) < 2  sql=%s", sql)
            return False, "the userId not exists"

        dbRegin = oneRec[0]
        dbSecretKey = oneRec[1]

        if dbRegin != region:
            return False, "the region is invalid"

        if len(dbSecretKey) <= 0:
            return False, "secret key of the userId is invalid"

        totalStr = region + userId + timestamp + random
        hmac_code = hmac.new(dbSecretKey.encode(), totalStr.encode(), sha1).digest()
        MySignature = base64.urlsafe_b64encode(hmac_code).decode()
        if signature != MySignature:
            return False, "the signature is invalid"

    return True, "OK"


def getImgPath(imgUrl: str = '', files: dict = None, param_name='file'):
    if len(imgUrl) <= 0 and (param_name not in files):
        return False, comFuncs.getFailedJson(comFuncs.ERR_CODE_SOME_PARA_INVALID,
                                             'imgUrl is empty  and file is not given')

    cfgJson = globalM.get_value("g_cfgJson")
    cfgDir = os.path.join(cfgJson['comonDir'], cfgJson['imgDir'])
    dateDir = datetime.datetime.now().strftime('%Y-%m-%d')
    uploadDir = os.path.join(cfgDir, dateDir)

    # 创建以日期命名的文件夹
    if not os.path.exists(uploadDir):
        os.makedirs(uploadDir)

    remoteF = None
    meta = None
    fileName = None

    if len(imgUrl) > 0:  # 远端文件
        fileName = imgUrl.rsplit('/')[-1]
        try:
            remoteF = urllib.request.urlopen(imgUrl, timeout=5)
        except:
            return False, comFuncs.getFailedJson(comFuncs.ERR_CODE_SOME_PARA_INVALID,
                                                 'The param(imgUrl {} ) is invalid'.format(imgUrl))
    else:  # 直接post上来的文件
        fileMetas = files[param_name]
        for meta in fileMetas:
            fileName = meta['filename']
            break

    if fileName is None:
        return False, comFuncs.getFailedJson(comFuncs.ERR_CODE_SOME_PARA_INVALID, 'Param(file or imgUrl) is invalid')

    fileSuf = fileName.rsplit('.', 1)
    if len(fileSuf) >= 2:
        fileName = fileSuf[0] + '_' + comFuncs.GetTimeRand() + '.' + fileSuf[1]
    else:
        fileName = fileName + '_' + comFuncs.GetTimeRand()

    imgPath = os.path.join(uploadDir, fileName)
    try:
        with open(imgPath, "wb") as localF:
            if len(imgUrl) > 0:
                localF.write(remoteF.read())
                remoteF.close()
                logging.info("post imgUrl (%s)", imgUrl)
            elif meta is not None:
                localF.write(meta['body'])
                logging.info("post file, save in (%s)", imgPath)
    except:
        return False, comFuncs.getFailedJson(comFuncs.ERR_CODE_OPEN_FILE_FAILED, 'fileName=%s' % fileName)

    return True, imgPath

#内部使用的获得卡证图片的接口
class FindCardHandler(tornado.web.RequestHandler):
    def get(self):
        pass
    def post(self):
        """
        ---
        tags:
        - 内部接口
        summary: 内部使用的获得卡证图片的接口
        description: 通过上传图片或者指定URL，获得如行驶证的图片
        parameters:
          -  name: file
             in: formData
             description: 所上传的图片，格式为JPG。 file， imgUrl 必须提供一个，如果都提供，只使用 imgUrl。
             required: false
             type: file

          -  name: imgUrl
             in: formData
             description: 图片的URL地址，图片格式为JPG
             required: false
             type: string

        responses:
            200:
              description: 应用层不管成功还是失败，都返回200
              schema:
                $ref: '#/definitions/responseObj'
        """

        imgUrl = self.get_argument("imgUrl", "")

        # 处理上传的文件或者从指定URL下载文件到本地
        ret, imgPath = getImgPath(imgUrl, self.request.files)
        if ret == False:
            self.write(imgPath)
            return False

        size = os.path.getsize(imgPath)
        if size <= 0:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED, "The image is invalid"))
            return False

        findIdCard = globalM.get_value("g_findIdCard")
        if findIdCard is None:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED))
            return False

        #destPath = imgPath.rsplit('.', 1)[0] + '_id.jpg'
        try:
            jsPos = findIdCard.find(imgPath)
        except:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED))
            return False


        result = {}
        '''
        cfgJson = globalM.get_value("g_cfgJson")
        commonDir = cfgJson['comonDir']
        result['url'] = os.path.join(cfgJson['imgUrlHost'], destPath[len(commonDir) + 1:])
        jsPos = {
            "PlateNo": [195, 150, 540, 225],
            "Model": [635, 450, 1250, 545],
            "Seal": [5, 538, 340, 870],
            "Vin": [570, 550, 1240, 650],
            "EngineNo": [545, 660, 1080, 750],
            "IssueDate": [950, 765, 1270, 860],
            "RegisterDate": [495, 765, 810, 855],
            "UseCharacter": [197, 450, 450, 540],
            "Address": [197, 340, 1260, 440],
            "VehicleType": [720, 140, 1250, 230],
            "Owner": [192, 235, 780, 335]
        }
        '''
        result['pos'] = jsPos

        self.write(comFuncs.getSucceedJson(result))

#内部使用的简易接口
class UploadFileHandler(tornado.web.RequestHandler):
    def get(self):
        pass

    #@tornado.gen.coroutine
    async def post(self):
        """
        ---
        tags:
        - 内部接口
        summary: 内部使用的简易识别接口
        description: 通过上传图片或者指定图片的URL，获得文字识别结果。
        parameters:
          -  name: reqId
             in: formData
             description: 请求ID，标识唯一请求，全流程跟踪使用
             required: false
             type: string
             
          -  name: userId
             in: formData
             description: 用户ID，用来区分不同的用户，统计及分类的时候使用
             required: false
             type: string

          -  name: userKey
             in: formData
             description: 用户Key， 如0dc8e5ff-823c-49d4-9b09-9c96c6d37513-357
             required: true
             type: string

          -  name: file
             in: formData
             description: 所上传的图片，格式为JPG。 file， imgUrl 必须提供一个，如果都提供，只使用 imgUrl。
             required: false
             type: file

          -  name: imgUrl
             in: formData
             description: 图片的URL地址，图片格式为JPG
             required: false
             type: string

          -  name: company
             in: formData
             description: 保单所属公司，当前支持的保险公司包括：华夏、泰康、平安、国寿、太平洋、长城、富德、人保、太平、天安、新华10版、新华17版、
                          阳光、中荷、中意、中英、百年16版、百年18版、光大、华泰、农银、信泰、友邦、中美、中信、同方、招商10版、招商17版
                          [ "huaxia", "taikang", "pingan", "guoshou", "taipingyang", "changcheng", "fude", "renbao",
                            "taiping", "tianan", "xinhua_10", "xinhua_17", "yangguang", "zhonghe", "zhongyi", "zhongying",
                            "bainian_16", "bainian_18", "guangda", "huatai", "nongyin", "xintai", "youbang", "zhongmei",
                            "zhongxin", "tongfang", "tongfang_19", "zhaoshang_10", "zhaoshang_17", "other"]
             required: false
             type: string

          -  name: regFields
             in: formData
             description: 识别的小区域个数，默认为100
             required: false
             type : integer
             format: int32

          -  name: delImg
             in: formData
             description: 是否删除图片，0为不删除，1为删除，默认为0
             required: false
             type: int
             format: int32

        responses:
            200:
              description: 应用层不管成功还是失败，都返回200
              schema:
                $ref: '#/definitions/responseObj'
        """

        #if redisMng.reach_concurrent_num(redisMng.G_INTERNAL_USER):
            #self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_REACH_MAX_CONCURRENT))
            #return

        try:
            await self.fun_UploadFileHandler()
        except Exception as e:
            logging.info('fun_UploadFileHandler except. e={}'.format(e))
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED))
            return

        #redisMng.release_concurrent_num(redisMng.G_INTERNAL_USER)

    #@run_on_executor
    async def fun_UploadFileHandler(self):
        regFields = self.get_argument('regFields', '100')
        imgUrl = self.get_argument("imgUrl", "")
        company = self.get_argument("company", "")
        myUUID = self.get_argument("reqId", "")
        userId = self.get_argument("userId", "internalUser_bd")
        userKey = self.get_argument("userKey", "")
        delImg = self.get_argument("delImg", "0")
        
        if len(myUUID) <= 0:
            myUUID = str(uuid.uuid1())
        else:
            logging.info('Given the reqId {}'.format(myUUID))

        logging.info('UploadFileHandler, reqId={}, userId={}, userKey={}, imgUrl={}, delImg={}'.format(
            myUUID, userId, userKey, imgUrl, delImg))
            
        # dict_user_info = globalM.get_value("g_userInfo")
        # if dict_user_info is not None:
        #     if userKey not in dict_user_info:
        #         self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_KEY, "userKey={}".format(userKey)))
        #         return
        #     one_user = dict_user_info[userKey]
        #     if 'Level' not in one_user:
        #         self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_KEY,
        #                                           "userKey={}, one_user={}".format(userKey, one_user)))
        #         return

        startT = time.time()
        # 处理上传的文件或者从指定URL下载文件到本地
        ret, imgPath = getImgPath(imgUrl, self.request.files)
        if ret == False:
            self.write(imgPath)
            return

        logging.info('reqId={}, getImgPath, imgPath={}, spend time: {:.1f}ms'.format(
            myUUID, imgPath, (time.time() - startT) * 1000))
        startT = time.time()

        outPosList = []
        outTextList = []
        need_detect = True

        is_pdf_file = False
        pdf_suffix = imgPath[-4:].lower()
        if pdf_suffix in ['.jpg', 'jpeg', '.png', 'tiff', '.gif']:  #为提升效率，尽量匹配字符串
            is_pdf_file = False
        elif pdf_suffix == '.pdf':  #为提升效率，尽量匹配字符串
            is_pdf_file = True
        elif comFuncs.get_file_type(imgPath) == 'pdf':  #不得已才走这一步
            is_pdf_file = True
            dest_path = imgPath + '.pdf'
            shutil.move(imgPath, dest_path)
            imgPath = dest_path

        if is_pdf_file:
            #直接读pdf的文字，格式不统一，很难解析，暂时注释掉
            #outPosList, outTextList = comFuncs.get_pdf_text(imgPath)
            outPosList = None
            if outPosList is None:
                img_list = comFuncs.pdf_to_png_fitz(imgPath, page_num=1, img_quality=2.8)
                if not img_list or len(img_list) <= 0:
                    self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_PDF_TO_IMG_FAILED, myUUID=myUUID))
                    return
                imgPath = img_list[0]
            else:
                need_detect = False

        if need_detect:
            # 开始检测
            txtPath = detect.detect_one(imgPath)
            logging.info('reqId={}, detect_one, txtPath={}, spend time: {:.1f}ms'.format(
                myUUID, txtPath, (time.time() - startT) * 1000))
            startT = time.time()
            if txtPath is None or len(txtPath) <= 0:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_DETECT_FAILED, myUUID=myUUID))
                return

            # 开始识别
            bRet, outPosList, outTextList = recog.recognize_one(imgPath, txtPath, int(regFields))

            logging.info('reqId={}, recognize_one, txtPath={}, spend time: {:.1f}ms'.format(
                myUUID, txtPath, (time.time() - startT) * 1000))
            startT = time.time()

            if not bRet:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED,
                                                  "recognize failed! imgPath=%s" % imgPath, myUUID=myUUID))
                return

        # 做信息解析
        keywordsObj = globalM.get_value("g_KeyWords")
        info, isPolicy, line_content, nlp_flag = InfoParse.infoParse(company, outPosList, outTextList, keywordsObj)

        logging.info('reqId={}, after InfoParse.infoParse, isPolicy={}, spend time: {:.1f}ms'.format(
            myUUID, isPolicy, (time.time() - startT) * 1000))
        startT = time.time()

        # 准备数据返回
        result = {}
        fmtInfo = {}
        cfgJson = globalM.get_value("g_cfgJson")

        if isPolicy:
            if nlp_flag:
                fmtInfo = info
            else:
                fmtInfo = comFuncs.getPolicyOutput(info)
                # 二次解析，如果:投被保人姓名，险种太少，无保费


            if 1 != cfgJson.get("is_formal"):  # 测试环境
                result['parsed'] = info
                result['line_content'] = line_content
            # 默认为寿险保单
            result["type"] = "0"
            policyType = fmtInfo.get("policyType")
            if policyType:
                if policyType == "车险":
                    result["type"] = "1"
            result['finalInfo'] = fmtInfo
        else:
            if 1 == cfgJson.get("is_formal"):  # 正式环境
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_POLICY,
                                                  "recognize failed! imgPath=%s" % imgPath, myUUID=myUUID))
                return
            else:
                result['finalInfo'] = info

        cfgJson = globalM.get_value("g_cfgJson")
        commonDir = cfgJson['comonDir']
        #result['url'] = os.path.join(cfgJson['imgUrlHost'], imgPath[len(commonDir) + 1:])
        
        txtList = []


        count = 0
        for one_text in outTextList:
            onePos = outPosList[count]
            oneObj = {}
            oneObj['pos'] = onePos
            oneObj['text'] = one_text
            txtList.append(oneObj)
            count += 1

        if 1 != cfgJson.get("is_formal"):  # 测试环境
            result['origInfo'] = txtList


        upload_url, pub_upload = workThreads.get_fs_load_url()

        if delImg == '1':
            os.remove(imgPath)
        else:
            if pub_upload is not None:
                result['url'] = pub_upload
            else:
                result['url'] = os.path.join(cfgJson['imgUrlHost'], imgPath[len(commonDir) + 1:])

            # 操作入库
            threadParam = {}
            threadParam['opType'] = 'record2Db'
            threadParam['userId'] = userId
            threadParam['picPath'] = [imgPath]
            threadParam['reqId'] = myUUID
            threadParam['finalInfo'] = fmtInfo
            threadParam['origInfo'] = txtList
            threadParam['result'] = 0

            threadParam['upload_url'] = [upload_url]
            threadParam['pub_upload'] = [pub_upload]

            #threadPool = globalM.get_value("g_threadPool")
            #threadPool.submit(workThreads.workThread, threadParam)
            workThreads.workThread(threadParam)
            # result['url'] = workThreads.workThread(threadParam)

            #endT = time.time()
            # logging.info('Upload to FS and to DB spend %.03fms  ', (endT - startT) * 1000)

        logging.info('reqId={}, result = {}, spend time: {:.1f}ms'.format(
            myUUID, info, (time.time() - startT) * 1000))
        self.write(comFuncs.getSucceedJson(infoV=result, myUUID=myUUID))

        return

#分类型的精准识别接口
class PolicyHandler(tornado.web.RequestHandler):
    def get(self):
        pass

    #@tornado.gen.coroutine
    async def post(self):

        """
        ---
        tags:
        - 对外接口
        summary: 高精准的通用识别接口
        description: 通过上传图片或者给出URL地址，返回识别结果
        parameters:
          -  name: reqId
             in: formData
             description: 请求ID，标识唯一请求，全流程跟踪使用
             required: false
             type: string

          -  name: userId
             in: formData
             description: 用户ID，如352ce7c689a372b6195cb690ec234521f970a665
             required: false
             type: string

          -  name: userKey
             in: formData
             description: 用户Key， 如0dc8e5ff-823c-49d4-9b09-9c96c6d37513-357
             required: true
             type: string

          -  name: file
             in: formData
             description: 所上传的图片，格式为JPG。 file， imgUrl 必须提供一个，如果都提供，只使用 imgUrl。
             required: false
             type: file

          -  name: imgUrl
             in: formData
             description: 图片的URL地址，图片格式为JPG
             required: false
             type: string

        responses:
            200:
              description: 应用层不管成功还是失败，都返回200
              schema:
                $ref: '#/definitions/responseObj'
        """
        try:
            await self.fun_PolicyHandler()
        except Exception as e:
            logging.info('fun_PolicyHandler except. e={}'.format(e))
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED))
            return

        #self.executor = globalM.get_value("g_threadPool")
        #yield self.fun_PolicyHandler()


    #@run_on_executor
    async def fun_PolicyHandler(self):

        myUUID = self.get_argument("reqId", "")
        userId = self.get_argument("userId", "")
        userKey = self.get_argument("userKey", "")
        imgUrl = self.get_argument("imgUrl", "")
        regType = self.get_argument("regType", '0')

        iRegType = int(regType)

        if len(myUUID) <= 0:
            myUUID = str(uuid.uuid1())

        logging.info("reqId=%s,userId=%s,userKey=%s,imgUrl=%s,regType=%s",
                     myUUID, userId, userKey, imgUrl, regType)

        dict_user_info = globalM.get_value("g_userInfo")
        if dict_user_info is not None:
            if userKey not in dict_user_info:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_KEY, "userKey={}".format(userKey)))
                return
            one_user = dict_user_info[userKey]
            if 'Level' not in one_user:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_KEY,
                                                  "userKey={}, one_user={}".format(userKey, one_user)))
                return

        ret, imgPath = getImgPath(imgUrl, self.request.files)
        if ret == False:
            self.write(imgPath)
            return

        cfgJson = globalM.get_value("g_cfgJson")
        commonDir = cfgJson['comonDir']
        requestUrl = os.path.join(cfgJson['imgUrlHost'], urllib.parse.quote(imgPath[len(commonDir) + 1:]))
        response = recog.recog_from_tencent(requestUrl, iRegType)

        if len(response) <= 0:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED))
            return

        #logging.info('response={}'.format(response))

        jsData = {}
        if 0 == iRegType:  # 通用识别
            #jsData = info_parse.infoParse(response)
            jsData['origInfo'] = info_parse.parse_orig(response)
            self.write(comFuncs.getSucceedJson(jsData, myUUID))
        elif 1 == iRegType:  # 行驶证识别
            try:
                jsRes = json.loads(response)
                jsData = jsRes['FrontInfo']
                #if 'Seal' in jsData:
                    #sealValue = jsData.pop('Seal')
                    #jsData['SealDesc'] = sealValue
                self.write(comFuncs.getSucceedJson(jsData, myUUID))
            except:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED))
                return


        # 操作入库
        threadParam = {}

        upload_url, pub_upload = workThreads.get_fs_load_url()

        threadParam['opType'] = 'record2Db'
        threadParam['userId'] = userId
        threadParam['picPath'] = [imgPath]
        threadParam['reqId'] = myUUID
        threadParam['finalInfo'] = {}
        threadParam['origInfo'] = {}
        threadParam['upload_url'] = [upload_url]
        threadParam['pub_upload'] = [pub_upload]

        if 0 == iRegType:
            if  'finalInfo' in jsData:
                threadParam['finalInfo'] = jsData['finalInfo']
            if  'origInfo' in jsData:
                threadParam['origInfo'] = jsData['origInfo']
        elif 1== iRegType:
            threadParam['finalInfo'] = jsData
            threadParam['origInfo'] = {}

        threadParam['result'] = 0
        #threadPool = globalM.get_value("g_threadPool")
        workThreads.workThread(threadParam)


#营业执照高精准识别接口，调用百度的，账号使用刘周可的
class BusinessLicenseHandler(tornado.web.RequestHandler):
    def get(self):
        pass

    #@tornado.gen.coroutine
    async def post(self):

        """
        ---
        tags:
        - 对外接口
        summary: 营业执照高精准识别接口
        description: 通过上传图片或者给出URL地址，返回识别结果
        parameters:
          -  name: reqId
             in: formData
             description: 请求ID，标识唯一请求，全流程跟踪使用
             required: false
             type: string

          -  name: userId
             in: formData
             description: 用户ID，如352ce7c689a372b6195cb690ec234521f970a665
             required: false
             type: string

          -  name: userKey
             in: formData
             description: 用户Key， 如0dc8e5ff-823c-49d4-9b09-9c96c6d37513-357
             required: true
             type: string

          -  name: file
             in: formData
             description: 所上传的图片，格式为JPG。 file， imgUrl 必须提供一个，如果都提供，只使用 imgUrl。
             required: false
             type: file

          -  name: imgUrl
             in: formData
             description: 图片的URL地址，图片格式为JPG
             required: false
             type: string

        responses:
            200:
              description: 应用层不管成功还是失败，都返回200
              schema:
                $ref: '#/definitions/responseObj'
        """

        try:
            await self.fun_BusinessLicenseHandler()
        except Exception as e:
            logging.info('fun_PolicyHandler except. e={}'.format(e))
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED))
            return

        #self.executor = globalM.get_value("g_threadPool")
        #yield self.fun_BusinessLicenseHandler()


    #@run_on_executor
    async def fun_BusinessLicenseHandler(self):

        myUUID = self.get_argument("reqId", "")
        userId = self.get_argument("userId", "")
        userKey = self.get_argument("userKey", "")
        imgUrl = self.get_argument("imgUrl", "")
        regType = self.get_argument("regType", '0')

        iRegType = int(regType)

        if len(myUUID) <= 0:
            myUUID = str(uuid.uuid1())

        logging.info("reqId=%s,userId=%s,userKey=%s,imgUrl=%s,regType=%s",
                     myUUID, userId, userKey, imgUrl, regType)

        dict_user_info = globalM.get_value("g_userInfo")
        if dict_user_info is not None:
            if userKey not in dict_user_info:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_KEY, "userKey={}".format(userKey)))
                return
            one_user = dict_user_info[userKey]
            if 'Level' not in one_user:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_KEY,
                                                  "userKey={}, one_user={}".format(userKey, one_user)))
                return

        ret, imgPath = getImgPath(imgUrl, self.request.files)
        if ret == False:
            self.write(imgPath)
            return

        headers = {'content-type': 'application/x-www-form-urlencoded'}

        client_id = 'dbh9pralHRybHkcsmpRIkQC8'
        client_secret = 'p7D7zZ1uCErZBtoo2f2iiaFtWyBndBuY'
        req_pre = 'https://aip.baidubce.com/oauth/2.0/token?grant_type=client_credentials'
        req_url = '{}&client_id={}&client_secret={}'.format(
            req_pre, client_id, client_secret
        )
        response = requests.post(req_url, headers=headers)
        access_token = '24.4c58fa6be24a8e987e1d8966ac7017e0.2592000.1605688395.282335-17921779'
        if response:
            access_token = response.json()['access_token']
            logging.info('access_token={}'.format(access_token))

        request_url = "https://aip.baidubce.com/rest/2.0/ocr/v1/business_license"
        # 二进制方式打开图片文件
        f = open(imgPath, 'rb')
        img = base64.b64encode(f.read())

        params = {"image": img}

        request_url = request_url + "?access_token=" + access_token

        response = requests.post(request_url, data=params, headers=headers)
        dict_ret = {}
        if response:
            # print(response.json())
            result_js = response.json()['words_result']

            for key in result_js:
                one_dict = result_js[key]
                dict_one = {}
                dict_one['text'] = one_dict['words']
                dict_one['loc'] = one_dict['location']
                if dict_one['loc']['top'] < 0:
                    dict_one['loc']['top'] = 0
                else:
                    dict_one['loc']['top'] = dict_one['loc']['top'] + 1
                    dict_one['loc']['height'] = dict_one['loc']['height'] - 1

                if dict_one['loc']['left'] < 0:
                    dict_one['loc']['left'] = 0
                else:
                    dict_one['loc']['left'] = dict_one['loc']['left'] + 1
                    dict_one['loc']['width'] = dict_one['loc']['width'] - 1

                dict_ret[key] = dict_one

            print(dict_ret)

        self.write(comFuncs.getSucceedJson(dict_ret, myUUID))


        # 操作入库
        threadParam = {}

        upload_url, pub_upload = workThreads.get_fs_load_url()

        threadParam['opType'] = 'record2Db'
        threadParam['userId'] = userId
        threadParam['picPath'] = [imgPath]
        threadParam['reqId'] = myUUID
        threadParam['finalInfo'] = {}
        threadParam['origInfo'] = {}
        threadParam['upload_url'] = [upload_url]
        threadParam['pub_upload'] = [pub_upload]

        threadParam['finalInfo'] = dict_ret

        threadParam['result'] = 0
        #threadPool = globalM.get_value("g_threadPool")
        workThreads.workThread(threadParam)


#表格识别接口，调用百度接口，账号使用张忠旭的
class FormOcrHandler(tornado.web.RequestHandler):
    def get(self):
        pass

    #@tornado.gen.coroutine
    async def post(self):

        """
        ---
        tags:
        - 对外接口
        summary: 表格识别高精准识别接口
        description: 通过上传图片或者给出URL地址，返回识别结果
        parameters:
          -  name: reqId
             in: formData
             description: 请求ID，标识唯一请求，全流程跟踪使用
             required: false
             type: string

          -  name: userId
             in: formData
             description: 用户ID，如352ce7c689a372b6195cb690ec234521f970a665
             required: false
             type: string

          -  name: userKey
             in: formData
             description: 用户Key， 如0dc8e5ff-823c-49d4-9b09-9c96c6d37513-357
             required: true
             type: string

          -  name: file
             in: formData
             description: 所上传的图片，格式为JPG。 file， imgUrl 必须提供一个，如果都提供，只使用 imgUrl。
             required: false
             type: file

          -  name: imgUrl
             in: formData
             description: 图片的URL地址，图片格式为JPG
             required: false
             type: string

        responses:
            200:
              description: 应用层不管成功还是失败，都返回200
              schema:
                $ref: '#/definitions/responseObj'
        """

        try:
            await self.fun_FormOcrHandler()
        except Exception as e:
            logging.info('fun_FormOcrHandler except. e={}'.format(e))
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED))
            return


    #@run_on_executor
    async def fun_FormOcrHandler(self):

        myUUID = self.get_argument("reqId", "")
        userId = self.get_argument("userId", "")
        userKey = self.get_argument("userKey", "")
        imgUrl = self.get_argument("imgUrl", "")

        if len(myUUID) <= 0:
            myUUID = str(uuid.uuid1())

        logging.info("reqId=%s,userId=%s,userKey=%s,imgUrl=%s", myUUID, userId, userKey, imgUrl)

        dict_user_info = globalM.get_value("g_userInfo")
        if dict_user_info is not None:
            if userKey not in dict_user_info:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_KEY, "userKey={}".format(userKey)))
                return
            one_user = dict_user_info[userKey]
            if 'Level' not in one_user:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_KEY,
                                                  "userKey={}, one_user={}".format(userKey, one_user)))
                return

        ret, imgPath = getImgPath(imgUrl, self.request.files)
        if ret == False:
            self.write(imgPath)
            return

        file_name = '1'
        if self.request.files is not None:
            fileMetas = self.request.files['file']
            for meta in fileMetas:
                file_name = meta['filename']
                break


        client_id = 'wqgu1187LjRQoPyPDymGgG7Y'
        client_secret = 'zvIhQ5ZPA3QlsEBfZGOuf8oFWtraynvr'
        req_pre = 'https://aip.baidubce.com/oauth/2.0/token?grant_type=client_credentials'
        req_url = '{}&client_id={}&client_secret={}'.format(
            req_pre, client_id, client_secret
        )
        logging.info("req_url={}".format(req_url))
        response = requests.get(req_url)
        access_token = ''
        if response:
            access_token = response.json()['access_token']
            logging.info('access_token={}'.format(access_token))

        headers = {'content-type': 'application/x-www-form-urlencoded'}

        request_url = "https://aip.baidubce.com/rest/2.0/solution/v1/form_ocr/request"
        # 二进制方式打开图片文件
        f = open(imgPath, 'rb')
        img = base64.b64encode(f.read())

        params = {"image": img}

        request_url = request_url + "?access_token=" + access_token

        response = requests.post(request_url, data=params, headers=headers)
        #logging.info("response = {}".format(response))
        dict_ret = {}
        if response:
            logging.info(response.json())
            result_js = response.json()
            result_data = ''
            for one_ret in result_js['result']:
                request_id = one_ret['request_id']
                for i in range(10):
                    time.sleep(1)
                    # 获取结果
                    request_url = "https://aip.baidubce.com/rest/2.0/solution/v1/form_ocr/get_request_result"
                    params = {"request_id": request_id}  # ,'result_type':'json'}
                    #params = {"request_id": request_id, 'result_type': 'json'}
                    request_url = request_url + "?access_token=" + access_token
                    headers = {'content-type': 'application/x-www-form-urlencoded'}
                    #logging.info('i = {}, url = {}'.format(i, request_url))
                    response = requests.post(request_url, data=params, headers=headers)
                    if response:
                        get_ret = response.json()['result']
                        if get_ret['percent'] >= 100:
                            result_data = get_ret['result_data']
                            break

                break

            dict_ret[file_name] = result_data

        self.write(comFuncs.getSucceedJson(dict_ret, myUUID))


        # 操作入库
        threadParam = {}

        upload_url, pub_upload = workThreads.get_fs_load_url()

        threadParam['opType'] = 'record2Db'
        threadParam['userId'] = userId
        threadParam['picPath'] = [imgPath]
        threadParam['reqId'] = myUUID
        threadParam['finalInfo'] = {}
        threadParam['origInfo'] = {}
        threadParam['upload_url'] = [upload_url]
        threadParam['pub_upload'] = [pub_upload]

        threadParam['finalInfo'] = dict_ret

        threadParam['result'] = 0
        #threadPool = globalM.get_value("g_threadPool")
        workThreads.workThread(threadParam)


#表格识别接口，调用阿里接口，账号使用刘周可的
class FormOcrHandler2(tornado.web.RequestHandler):
    def get(self):
        pass

    #@tornado.gen.coroutine
    async def post(self):

        """
        ---
        tags:
        - 对外接口
        summary: 表格识别高精准识别接口2
        description: 通过上传图片或者给出URL地址，返回识别结果
        parameters:
          -  name: reqId
             in: formData
             description: 请求ID，标识唯一请求，全流程跟踪使用
             required: false
             type: string

          -  name: userId
             in: formData
             description: 用户ID，如352ce7c689a372b6195cb690ec234521f970a665
             required: false
             type: string

          -  name: userKey
             in: formData
             description: 用户Key， 如0dc8e5ff-823c-49d4-9b09-9c96c6d37513-357
             required: true
             type: string

          -  name: file
             in: formData
             description: 所上传的图片，格式为JPG。 file， imgUrl 必须提供一个，如果都提供，只使用 imgUrl。
             required: false
             type: file

          -  name: imgUrl
             in: formData
             description: 图片的URL地址，图片格式为JPG
             required: false
             type: string

        responses:
            200:
              description: 应用层不管成功还是失败，都返回200
              schema:
                $ref: '#/definitions/responseObj'
        """

        try:
            await self.fun_FormOcrHandler2()
        except Exception as e:
            logging.info('fun_FormOcrHandler2 except. e={}'.format(e))
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED))
            return


    #@run_on_executor
    async def fun_FormOcrHandler2(self):

        myUUID = self.get_argument("reqId", "")
        userId = self.get_argument("userId", "")
        userKey = self.get_argument("userKey", "")
        imgUrl = self.get_argument("imgUrl", "")

        if len(myUUID) <= 0:
            myUUID = str(uuid.uuid1())

        logging.info("reqId=%s,userId=%s,userKey=%s,imgUrl=%s", myUUID, userId, userKey, imgUrl)

        dict_user_info = globalM.get_value("g_userInfo")
        if dict_user_info is not None:
            if userKey not in dict_user_info:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_KEY, "userKey={}".format(userKey)))
                return
            one_user = dict_user_info[userKey]
            if 'Level' not in one_user:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_KEY,
                                                  "userKey={}, one_user={}".format(userKey, one_user)))
                return

        ret, imgPath = getImgPath(imgUrl, self.request.files)
        if ret == False:
            self.write(imgPath)
            return

        file_name = '1'
        if self.request.files is not None:
            fileMetas = self.request.files['file']
            for meta in fileMetas:
                file_name = meta['filename']
                break

        dict_ret = {}
        with open(imgPath, 'rb') as f:  # 以二进制读取本地图片
            data = f.read()
            encodestr = str(base64.b64encode(data), 'utf-8')

            AppCode = "31ade35180b44015a94421f00580eb6b"
            headers = {
                'Authorization': 'APPCODE ' + AppCode,
                'Content-Type': 'application/json; charset=UTF-8'
            }

            request_url = 'https://ocrapi-advanced.taobao.com/ocrservice/advanced'
            dict = {'img': encodestr}
            params = json.dumps(dict).encode(encoding='UTF8')

            logging.info('Before Request, request_url={}'.format(request_url))
            req = urllib.request.Request(request_url, params, headers)
            r = urllib.request.urlopen(req)
            html = r.read()
            r.close()
            #return html.decode("utf8")

            #response = requests.post(request_url, data=params, headers=headers)
            dict_ret = html.decode("utf8")

            logging.info('response={}'.format(dict_ret))

            self.write(comFuncs.getSucceedJson(dict_ret, myUUID))



        # 操作入库
        threadParam = {}

        upload_url, pub_upload = workThreads.get_fs_load_url()

        threadParam['opType'] = 'record2Db'
        threadParam['userId'] = userId
        threadParam['picPath'] = [imgPath]
        threadParam['reqId'] = myUUID
        threadParam['finalInfo'] = {}
        threadParam['origInfo'] = {}
        threadParam['upload_url'] = [upload_url]
        threadParam['pub_upload'] = [pub_upload]

        threadParam['finalInfo'] = dict_ret

        threadParam['result'] = 0
        #threadPool = globalM.get_value("g_threadPool")
        workThreads.workThread(threadParam)


#提供给外面的正式接口
class PolicyRcgHandler(tornado.web.RequestHandler):
    def get(self):
        pass

    def post(self):

        """
        ---
        tags:
        - 对外接口
        summary: 通用识别接口
        description: 通过上传图片或者指定图片的URL，获得文字识别结果。
        parameters:
          -  name: region
             in: formData
             description: 用户所属区域，如shenzhen
             required: true
             type: string

          -  name: userId
             in: formData
             description: 用户ID，如352ce7c689a372b6195cb690ec234521f970a665
             required: true
             type: string

          -  name: timestamp
             in: formData
             description: 秒级时间戳，如1566353364。注意：如果与服务器时间相差超过5分钟，会报错
             required: true
             type: integer
             format: int32

          -  name: random
             in: formData
             description: 随机正整数，如23455，用于防止重放攻击
             required: true
             type: integer
             format: int32

          -  name: signature
             in: formData
             description: 使用 HMAC-SHA1 算法，对字符串（region + userId + timestamp + random）使用秘钥得到的签名
             required: true
             type: string

          -  name: file
             in: formData
             description: 所上传的图片，格式为JPG。 file， imgUrl 必须提供一个，如果都提供，只使用 imgUrl。
             required: false
             type: file

          -  name: imgUrl
             in: formData
             description: 图片的URL地址，图片格式为JPG
             required: false
             type: string

          -  name: company
             in: formData
             description: 保单所属公司，最好选上，能更精准地输出
             required: false
             type: string
             enum: [ "huaxia", "taikang", "pingan", "guoshou", "taipingyang", "changcheng", "fude", "renbao",
                   "taiping", "tianan", "xinhua_10", "xinhua_17", "yangguang", "zhonghe", "zhongyi", "zhongying",
                   "bainian", "guangda", "haikang", "hezhong", "huatai", "nongyin", "xintai", "youbang", "zhongmei",
                   "zhongxin", "tongfang", "tongfang_19", "zhaoshang_10", "zhaoshang_17"]

          -  name: regFields
             in: formData
             description: 识别的小区域个数，默认为100
             required: false
             type : integer
             format: int32

          -  name: templateName
             in: formData
             description: 输出模板名称，如果不指定，则按系统默认格式输出
             required: false
             type: string

        responses:
            200:
              description: 应用层不管成功还是失败，都返回200
              schema:
                $ref: '#/definitions/responseObj'
        """

        region = self.get_argument("region", "")
        userId = self.get_argument("userId", "")
        timestamp = self.get_argument("timestamp", "")
        random = self.get_argument("random", "")
        signature = self.get_argument("signature", "")
        imgUrl = self.get_argument("imgUrl", "")
        company = self.get_argument("company", "")
        regFields = self.get_argument("regFields", "100")
        templateKey = self.get_argument("templateName", "")

        logging.info("region=%s,userId=%s,timestamp=%s,random=%s,signature=%s,imgUrl=%s,regFields=%s,templateKey=%s",
                     region, userId, timestamp, random, signature, imgUrl, regFields, templateKey)

        ret, otherInfo = check_paras(region, userId, timestamp, random, signature)
        if ret == False:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_SOME_PARA_INVALID, otherInfo))
            return

        templatePath = ''
        keywordsObj = globalM.get_value("g_KeyWords")
        if len(templateKey) > 0:
            templatePath = redisMng.get_template_path(userId, templateKey)
            if len(templatePath) <= 0:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_SOME_PARA_INVALID,
                                                  "the templateName(%s) not exists" % templateKey))
                return

        ret, imgPath = getImgPath(imgUrl, self.request.files)
        if ret == False:
            self.write(imgPath)
            return

        txtPath = detect.detect_one(imgPath)
        if txtPath is None or len(txtPath) <= 0:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_DETECT_FAILED))
            return

        bRet, outPosList, outTextList = recog.recognize_one(imgPath, txtPath, int(regFields))

        if not bRet:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RECOGNIZE_FAILED,
                                              "recognize failed! imgPath=%s" % imgPath))
            return


        cfgJson = globalM.get_value("g_cfgJson")
        result = {}
        commonDir = cfgJson['comonDir']
        result['url'] = os.path.join(cfgJson['imgUrlHost'], imgPath[len(commonDir) + 1:])
        txtList = []

        info, isPolicy, _= InfoParse.infoParse(company, outPosList, outTextList, keywordsObj)

        # 准备数据返回
        result = {}
        if isPolicy == True:
            fmtInfo = comFuncs.getPolicyOutput(info)
            result['finalInfo'] = fmtInfo
        else:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_INVALID_POLICY,
                                              "recognize failed! imgPath=%s" % imgPath))
            return

            #result['finalInfo'] = info

        #result['finalInfo'] = InfoParse.infoParse(company, outPosList, outTextList, keywordsObj)

        count = 0
        for one_text in outTextList:
            onePos = outPosList[count]
            oneObj = {}
            oneObj['pos'] = onePos
            oneObj['text'] = one_text
            txtList.append(oneObj)
            count += 1

        #result['origInfo'] = txtList


        myUUID = str(uuid.uuid1())
        self.write(comFuncs.getSucceedJson(result, myUUID))

        #操作入库
        threadParam = {}
        threadParam['opType'] = 'record2Db'
        threadParam['userId'] = userId
        threadParam['picPath'] = imgPath
        threadParam['reqId'] = myUUID
        threadParam['finalInfo'] = result['finalInfo']
        threadParam['origInfo'] = txtList
        threadParam['result'] = 0

        #threadPool = globalM.get_value("g_threadPool")
        #threadPool.submit(workThreads.workThread, threadParam)
        workThreads.workThread(threadParam)

#回写识别结果
class UpdateRcgHandler(tornado.web.RequestHandler):
    def get(self):
        pass

    @tornado.gen.coroutine
    def post(self):
        """
         ---
         tags:
         - 内部接口
         summary: 回写识别结果
         description: 在核对并且修改识别结果之后，回写结果
         parameters:
           -  name: reqId
              in: formData
              description: 调用识别接口返回的reqId
              required: true
              type: string

           -  name: modInfo
              in: formData
              description: 修改后的结果，json格式的字符串
              required: true
              type: string

         responses:
             200:
               description: 应用层不管成功还是失败，都返回200
               schema:
                 $ref: '#/definitions/responseObj'
         """
        self.executor = globalM.get_value("g_threadPool")
        yield self.fun_UpdateRcgHandler()

    @run_on_executor
    def fun_UpdateRcgHandler(self):

        reqId = self.get_argument("reqId", "")
        modInfo = self.get_argument("modInfo", "")

        logging.info('UpdateRcgHandler, reqId={}, modInfo={}'.format( reqId, modInfo))

        if len(reqId) <= 0 or len(modInfo) <= 0:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_SOME_PARA_INVALID,
                                              "reqId is empty or modInfo is empty",
                                              myUUID=reqId))
            return

        with dbMng.getDbCurson() as myCur:
            if myCur is None:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_DB_OP_FAILED))
                return

            sql = "SELECT 1 FROM tbl_recognize WHERE ReqID = '%s' " % reqId
            myCur.execute(sql)
            oneRec = myCur.fetchone()
            if oneRec is None or len(oneRec) < 1:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_RID_NOT_EXISTE,
                                                  "reqId(%s) not exists" % reqId,
                                                  myUUID=reqId))
                return


        bHasErr = False
        modInfo = modInfo.replace('\'', '\"')
        sql = "UPDATE tbl_recognize SET ModInfo = '%s', LastTime = NOW() WHERE ReqID = '%s'" % (modInfo, reqId)
        #logging.info('UpdateRcgHandler, reqId={}, sql={}'.format(reqId, sql))

        myCon = dbMng.getDbCon()
        if myCon is None:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_DB_OP_FAILED, myUUID=reqId))
            return

        myCur2 = myCon.cursor()
        try:
            logging.info('Before myCur2.execute, len(sql)=%d', len(sql))
            myCur2.execute(sql)
            myCon.commit()
        except:
            bHasErr = True
            myCon.rollback()

        finally:
            myCur2.close()
            myCon.close()

        if bHasErr is True:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_DB_OP_FAILED, myUUID=reqId))
            logging.error("database operate failed! sql = %s !", sql)
            return

        logging.info('UpdateRcgHandler, before getSucceedJson, reqId={}'.format(reqId))
        self.write(comFuncs.getSucceedJson(myUUID=reqId))
        return

#修改指定key的模板
class ModTemplateHandler(tornado.web.RequestHandler):
    def get(self):
        pass

    def post(self):

        """
           -#--
           tags:
           - 对外接口
           summary: 上传或修改用户当前的模板信息
           description: 通过上传文件，修改指定Key的解析模板
           parameters:
             -  name: region
                in: formData
                description: 用户所属区域，如shenzhen
                required: true
                type: string

             -  name: userId
                in: formData
                description: 用户ID，如352ce7c689a372b6195cb690ec234521f970a665
                required: true
                type: string

             -  name: timestamp
                in: formData
                description: 秒级时间戳，如1566353364。注意：如果与服务器时间相差超过5分钟，会报错
                required: true
                type : integer
                format: int32

             -  name: random
                in: formData
                description: 随机正整数，如23455，用于防止重放攻击
                required: true
                type : integer
                format: int32

             -  name: signature
                in: formData
                description: 使用 HMAC-SHA1 算法，对字符串（region + userId + timestamp + random）使用秘钥得到的签名
                required: true
                type: string

             -  name: templateKey
                in: formData
                description: 模板的Key，可通过 /tndSrv/getTemplates 查看当前用户所有的模板信息
                required: true
                type: string

             -  name: file
                in: formData
                description: json格式的模板文件文件
                required: false
                type: file

           responses:
               200:
                 description: 应用层不管成功还是失败，都返回200
                 schema:
                   $ref: '#/definitions/responseObj'

           """

        region = self.get_argument("region", "")
        userId = self.get_argument("userId", "")
        timestamp = self.get_argument("timestamp", "")
        random = self.get_argument("random", "")
        signature = self.get_argument("signature", "")

        templateKey = self.get_argument("templateKey", "")

        logging.info("ModTemplateHandler， region=%s, userId=%s, timestamp=%s, random=%s, signature=%s， templateKey=%s",
                     region, userId, timestamp, random, signature, templateKey)

        ret, otherInfo = check_paras(region, userId, timestamp, random, signature)
        if ret == False:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_SOME_PARA_INVALID, otherInfo))
            return


        if len(templateKey) <= 0:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_SOME_PARA_INVALID, "templateKey is empty"))
            return

        cfgJson = globalM.get_value("g_cfgJson")
        templateDir = os.path.join(cfgJson['comonDir'], 'templates')

        if not os.path.exists(templateDir):
            os.makedirs(templateDir)

        meta = object
        fileName = None

        if len(self.request.files) > 0:
            file_metas = self.request.files.get('file')
            if file_metas is not None:
                for meta in file_metas:
                    fileName = meta['filename']
                    break

        if fileName is None:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_SOME_PARA_INVALID, "file is empty"))
            return

        fileSuf = fileName.rsplit('.', 1)
        if len(fileSuf) >= 2:
            fileName = fileSuf[0] + '_' + comFuncs.GetTimeRand() + '.' + fileSuf[1]
        else:
            fileName = fileName + '_' + comFuncs.GetTimeRand()

        filePath = os.path.join(templateDir, fileName)

        with open(filePath, "wb") as localF:
            localF.write(meta['body'])

        jsTemplates = {}
        with dbMng.getDbCurson() as myCur:
            if myCur is None:
                self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_DB_OP_FAILED))
                return

            sql = "SELECT jsTemplates FROM tbl_customer WHERE UserId='%s'" % userId
            myCur.execute(sql)
            row = myCur.fetchone()
            if row is not None and row[0] is not None and len(row[0]) > 0:
                try:
                    jsTemplates = json.loads(row[0])
                except:
                    jsTemplates = {}
                    logging.error("ModTemplateHandler, userId = %s, row[0] = %s   is not json", userId, row[0])

        jsTemplates[templateKey] = fileName

        bHasErr = False
        sql = "UPDATE tbl_customer SET jsTemplates = '%s' WHERE UserId = '%s'" % \
              (json.dumps(jsTemplates,skipkeys=False, ensure_ascii=False), userId)
        myCon = dbMng.getDbCon()
        if myCon is None:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_DB_OP_FAILED))
            return

        myCur2 = myCon.cursor()
        try:
            logging.info('Before myCur2.execute, len(sql)=%d', len(sql))
            myCur2.execute(sql)
            myCon.commit()
        except:
            bHasErr = True
            myCon.rollback()

        finally:
            myCur2.close()
            myCon.close()

        if bHasErr is True:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_DB_OP_FAILED))
            logging.error("database operate failed! sql = %s !", sql)
            return

        redisCon = redisMng.getRedisCon()
        if redisCon is not  None:
            redisCon.hset(redisMng.G_REDIS_USER_KEY + userId, redisMng.G_USER_FIELD_TEMPLATE + templateKey, fileName)

        jsResult = {}
        jsResult['templates'] = jsTemplates
        self.write(comFuncs.getSucceedJson(jsResult))
        return

#获取用户当前的模板信息
class GetTemplatesHandler(tornado.web.RequestHandler):
    def get(self):
        """
        -#--
        tags:
        - 对外接口
        summary: 获取用户当前的模板信息
        description: 可通过该接口查看用户目前所有的模板信息

        parameters:
          -  name: region
             in: query
             description: 用户所属区域，如shenzhen
             required: true
             type: string

          -  name: userId
             in: query
             description: 用户ID，如352ce7c689a372b6195cb690ec234521f970a665
             required: true
             type: string

          -  name: timestamp
             in: query
             description: 秒级时间戳，如1566353364。注意：如果与服务器时间相差超过5分钟，会报错
             required: true
             type : integer
             format: int32

          -  name: random
             in: query
             description: 随机正整数，如23455，用于防止重放攻击
             required: true
             type : integer
             format: int32

          -  name: signature
             in: query
             description: 使用 HMAC-SHA1 算法，对字符串（region + userId + timestamp + random）使用秘钥得到的签名
             required: true
             type: string

        responses:
            200:
              description: 应用层不管成功还是失败，都返回200
              schema:
                $ref: '#/definitions/responseObj'

        """

        region = self.get_argument("region", "")
        userId = self.get_argument("userId", "")
        timestamp = self.get_argument("timestamp", "")
        random = self.get_argument("random", "")
        signature = self.get_argument("signature", "")

        logging.info("GetTemplatesHandler， region=%s, userId=%s, timestamp=%s, random=%s, signature=%s",
                     region, userId, timestamp, random, signature)

        ret, otherInfo = check_paras(region, userId, timestamp, random, signature)
        if ret == False:
            self.write(comFuncs.getFailedJson(comFuncs.ERR_CODE_SOME_PARA_INVALID, otherInfo))
            return

        jsTemplates = {}
        with dbMng.getDbCurson() as myCur:
            sql = "SELECT jsTemplates FROM tbl_customer WHERE UserId='%s'" % userId
            myCur.execute(sql)
            row = myCur.fetchone()
            if row is not None and row[0] is not None and len(row[0]) > 0:
                try:
                    jsTemplates = json.loads(row[0])
                except:
                    jsTemplates = {}
                    logging.error("GetTemplatesHandler, userId = %s, row[0] = %s   is not json", userId, row[0])

        jsResult = {}
        jsResult['templates'] = jsTemplates
        self.write(comFuncs.getSucceedJson(jsResult))
        return

    def post(self):
        pass

#获取服务器的秒级时间戳
class GetServerTS(tornado.web.RequestHandler):
    def get(self):
        """
            ---
            tags:
            - 对外接口
            summary: 获取服务器的秒级时间戳

            responses:
                200:
                  description: 应用层不管成功还是失败，都返回200
                  schema:
                    $ref: '#/definitions/responseObj'
            """

        jsResult = {}
        jsResult['TS'] = int(time.time())
        self.write(comFuncs.getSucceedJson(jsResult))

    def post(self):
        pass
