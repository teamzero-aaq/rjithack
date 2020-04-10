import collections
from collections import OrderedDict
from datetime import datetime
from random import randint

import pyrebase
from cryptography.fernet import Fernet
from django.http import HttpResponseRedirect
from django.shortcuts import render
from pytesseract import pytesseract

from . import Common
from . import PyConfig
from .SendMail import sendmail


def generatedigitalsign(filen):
    # !/usr/bin/env vpython3
    # *-* coding: utf-8 *-*
    import datetime

    from cryptography.hazmat import backends
    from cryptography.hazmat.primitives.serialization import pkcs12
    from endesive import pdf

    # import logging
    # logging.basicConfig(level=logging.DEBUG)

    date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = date.strftime('%Y%m%d%H%M%S+00\'00\'')
    dct = {
        b'sigflags': 3,
        # b'sigpage': 0,
        b'sigbutton': True,
        b'signature_img': b'sign.png',
        b'contact': b'sohil.l@somaiya.edu',
        b'location': b'India',
        b'signingdate': date.encode(),
        b'reason': b'Verified Document',
        b'signature': b'Approved By Goverment',
        b'signaturebox': (470, 0, 570, 100),
    }
    with open('Key.p12', 'rb') as fp:
        p12 = pkcs12.load_key_and_certificates(fp.read(), b'Sky@76445', backends.default_backend())
    fname = filen
    datau = open(fname, 'rb').read()
    datas = pdf.cms.sign(datau, dct,
                         p12[0],
                         p12[1],
                         p12[2],
                         'sha256'
                         )
    fname = fname.replace('.pdf', '-signed.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


def connect_firebase():
    firebase = pyrebase.initialize_app(PyConfig.config1)
    auth = firebase.auth()
    db = firebase.database()
    return db


def connect_firebasesto():
    firebase = pyrebase.initialize_app(PyConfig.config1)
    auth = firebase.auth()
    dbs = firebase.storage()
    return dbs


def category(request, key):
    db = connect_firebase()
    schemes = OrderedDict()
    catname = request.GET['category']
    try:
        schemes = db.child("Scheme").order_by_child("level").equal_to(catname).get().val()
    except:
        print("Error")
    return render(request, 'category.html', {"scheme": schemes, "islog": Common.isLogin})


def home(request):
    db = connect_firebase()
    trusts = db.child("Trust").order_by_key().get().val()
    schemes = db.child("Scheme").order_by_key().limit_to_last(9).get().val()
    return render(request, 'home.html', {"scheme": schemes, "all_trusts": trusts, "islog": Common.isLogin})


def login(request):
    return render(request, 'login.html', {})


def test(request):
    return render(request, 'reported_user.html', {})


def test1(request):
    return render(request, 'ministries_dashboard.html', {})


def userpro(request):
    return render(request, 'profile_user.html', {"user": Common.currentUser})


def viewuserdoc(request):
    return render(request, 'user_doc_detail.html', {})


def adminlogin(request):
    return render(request, 'adminlogin.html', {})


def adminverify(request):
    adminname = request.POST.get('trust_username')
    password = request.POST.get('password')

    db = connect_firebase()
    username = db.child("Admin").child("username").get().val()
    passworddb = db.child("Admin").child("password").get().val()

    if adminname == username and password == passworddb:

        Common.isAdminLogin = True
        Common.admin = db.child("Admin").get().val()
        return HttpResponseRedirect('/adminhome')
    else:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Invalid Password or usrername",
                       "path": "admin-login"})


def adminhome(req):
    if (Common.isAdminLogin):
        data = OrderedDict()

        db = connect_firebase()
        try:
            data = db.child("Trust").get().val()
        except:
            pass

        print(data)
        return render(req, 'admin_home.html',
                      {"admin": Common.admin, "trusts": data})
    else:
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def addtrust(req):
    if (Common.isAdminLogin):

        timestamp = datetime.timestamp(datetime.now())
        trustkey = str(timestamp).replace('.', '')
        return render(req, 'addtrust.html',
                      {"admin": Common.admin, "trustkey": trustkey})
    else:
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def addtrustdb(request):
    if (Common.isAdminLogin):
        tname = request.POST['tname']
        tcontact = request.POST['tcontact']
        temailid = request.POST['temailid']
        tabout = request.POST['tabout']
        taddress = request.POST['taddress']
        tvision = request.POST['tvision']
        tpass = request.POST['tpass']
        tkey = request.POST['trustkey']
        logo = request.POST['trustlogourl']
        print(logo)
        tlogo = "https://firebasestorage.googleapis.com/v0/b/scholar-help-966a2.appspot.com/o/trust_logo%2F" + tkey + ".png?alt=media"

        db = connect_firebase()
        temail = None
        tphone = None

        try:
            temail = db.child("Trust").order_by_child("mailid").equal_to(temailid).get().val()
            print(temail + "mailid")
        except:
            pass
        try:

            tphone = db.child("Trust").order_by_child("contact").equal_to(tcontact).get().val()

        except:
            pass
        if temail:
            return render(request, 'redirecthome.html',
                          {"swicon": "error", "swtitle": "Error", "swmsg": "Trust Email Exists", "path": "addtrust"})
        elif tphone:
            return render(request, 'redirecthome.html',
                          {"swicon": "error", "swtitle": "Error", "swmsg": "Trust Phone Exists", "path": "addtrust"})
        else:

            data = {
                "name": tname, "contact": tcontact, "mailid": temailid,
                "about": tabout, "address": taddress, "vision": tvision, "password": tpass
                , "logo": tlogo, "username": tname

            }
            msgsend = "" \
                      "You have been register on scholarhelp. " \
                      "Your password is " \
                      "" + tpass + " ."
            print(data)

            db.child("Trust").child(str(tkey)).update(data)
            sendmail(temailid, "Successfully Registered on Scholar Help -" + tkey
                     , msgsend
                     )

            return render(request, 'redirecthome.html',
                          {"swicon": "success", "swtitle": "Done", "swmsg": "Trust Added Successfully",
                           "path": "adminhome"})

    else:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def adminedittrustview(req):
    if (Common.isAdminLogin):
        tkey = req.POST['tkey']
        db = connect_firebase()
        tru = db.child("Trust").child(str(tkey)).get().val()

        return render(req, 'admin_edit_trust.html',
                      {"trustkey": str(tkey), "trust_val": tru})
    else:
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def adminstudentview(req):
    if (Common.isAdminLogin):
        db = connect_firebase()
        try:
            data = db.child("users").get().val()
        except:
            pass

        print(data)
        return render(req, 'view_all_student.html',
                      {"admin": Common.admin, "Users": data})

    else:
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def studentprofile(req):
    if (Common.isAdminLogin):
        tkey = req.POST['tkey']
        db = connect_firebase()
        userprofile = None
        accno = None
        try:
            userprofile = db.child("UserProfile").child(str(tkey)).get().val()

            cipher = Fernet(Common.encyptionkey)
            accno = cipher.decrypt(userprofile.get("account_number").encode()).decode()

        except:
            pass
        return render(req, 'student_comp_profile.html',
                      {

                          "userprofile": userprofile, "accno": accno,

                      })


    else:
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def removestudent(req):
    if (Common.isAdminLogin):
        tkey = req.POST['tkey']
        db = connect_firebase()
        userprofile = None
        accno = None
        try:
            db.child("UserProfile").child(str(tkey)).remove()

        except:
            pass
        try:
            db.child("users").child(str(tkey)).remove()

        except:
            pass
        try:
            print(tkey + "user id")
            userapp = db.child("AppliedScheme").order_by_child("userid").equal_to(str(tkey)).get().val()
            all11 = db.child("AppliedScheme").get().val()
            all(map(all11.pop, userapp))
            db.child("AppliedScheme").set(all11)
        except:
            pass
        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Student Remove Successfully",
                       "path": "adminhome"})


    else:
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def removetrust(req):
    if (Common.isAdminLogin):
        tkey = req.POST['tkey']
        db = connect_firebase()
        userprofile = None
        print(tkey + " tt")
        accno = None
        try:
            tt = db.child("Trust").child(str(tkey)).remove()
            print(tt + " tt")

        except:
            pass

        try:

            tscheme = db.child("Scheme").order_by_child("trust_id").equal_to(str(tkey)).get().val()
            alls = db.child("Scheme").get().val()
            all(map(alls.pop, tscheme))
            db.child("Scheme").set(alls)
        except:
            pass
        try:

            ascheme = db.child("AppliedScheme").order_by_child("trust_id").equal_to(str(tkey)).get().val()
            allaps = db.child("AppliedScheme").get().val()
            all(map(allaps.pop, ascheme))
            db.child("AppliedScheme").set(allaps)
        except:
            pass
        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Trust Remove Successfully",
                       "path": "adminhome"})


    else:
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def adminupdattrust(request):
    if (Common.isAdminLogin):
        tname = request.POST['tname']
        tcontact = request.POST['tcontact']
        temailid = request.POST['temailid']
        tabout = request.POST['tabout']
        taddress = request.POST['taddress']
        tvision = request.POST['tvision']
        tpass = request.POST['tpass']
        tkey = request.POST['tkey']

        data = {
            "name": tname, "contact": tcontact, "mailid": temailid,
            "about": tabout, "address": taddress, "vision": tvision, "password": tpass
        }
        db = connect_firebase()
        db.child("Trust").child(tkey).update(data)

        return render(request, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Trust Updated Successfully",
                       "path": "adminhome"})

    else:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def applyscheme(req):
    db = connect_firebase()
    schemes = db.child("Scheme").order_by_key().limit_to_last(9).get().val()

    return render(req, 'viewallscheme.html',
                  {"scheme": schemes})


def trust_login(request):
    return render(request, 'trust_login.html', {})


def uplaoded_doc(request):
    return render(request, 'uploaded_document.html', {})


def pending_doc(request):
    return render(request, 'pending_document.html', {})


def user_aadhar_reg(request):
    return render(request, 'user_adhar_reg.html', {})


def sendotp(request):
    db = connect_firebase()
    user = OrderedDict()
    checkadhaar = request.POST['aadharno']
    try:
        user = db.child("AdharData").child(checkadhaar).get().val()
    except:
        print("Error")

    if not user:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Invalid Adhar Number",
                       "path": "user-aadhar-reg"})

    otp = str(randint(1000, 9999))

    Common.adharotp = otp
    print(otp, " is otp")
    Common.adharotptime = datetime.now()
    Common.tempuser = user
    title = "Adhar verification"
    msg = "Enter following OTP within 15 minutes.\nOTP is " + otp
    for key, value in user.items():
        Common.userphone = key
    print(user)
    sendmail(user.get("mail"), title, msg)
    return HttpResponseRedirect('/verifyotp')


def verifyotp(request):
    return render(request, 'verifyotp.html', {})


def checkotp(request):
    getOTP = request.POST['otp']
    diff = datetime.now() - Common.adharotptime
    otptime = diff.total_seconds()
    print('enter otp ', getOTP)
    print(' otp  is', Common.adharotptime)
    if getOTP != Common.adharotp:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Wrong OTP Entered", "path": "verifyotp"})
    elif otptime > 15 * 60:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "OTP Expired", "path": "login"})
    else:
        return HttpResponseRedirect('/user-reg')


def changepassword(request):
    return render(request, 'user-choosepass.html', {})


def user_reg(request):
    return render(request, 'user-choosepass.html', {"user": Common.tempuser})


def removethis(req):
    db = connect_firebase()
    db.child("users").child(str(335179014426)).update(
        {"enckey": Fernet.generate_key().decode()})

    return render(req, 'redirecthome.html',
                  {"swicon": "success", "swtitle": "Done", "swmsg": "Registration Successfully.",
                   "path": "login"})


def runmlalgo(req):
    from PIL import Image
    import requests
    from io import BytesIO

    response = requests.get(
        "https://firebasestorage.googleapis.com/v0/b/rgit-hack.appspot.com/o/Adhaar%20jpeg.JPG?alt=media&token=233861a1-1093-4b0f-908e-0feba7630621")
    image_path_in_colab = Image.open(BytesIO(response.content))

    # image_path_in_colab="https://i.ytimg.com/vi/zJFHOJDIX30/maxresdefault.jpg"
    # extractedInformation = pytesseract.image_to_string(Image.open(image_path_in_colab))
    extractedInformation = pytesseract.image_to_string(image_path_in_colab)
    print(extractedInformation)
    return render(req, 'redirecthome.html',
                  {"swicon": "success", "swtitle": "Done", "swmsg": extractedInformation,
                   "path": "login"})


def validatedoc(req):
    db = connect_firebase()
    sname = req.POST['sername']
    cno = req.POST['cno']
    name_doc = req.POST['name_doc']
    key = req.POST['key']
    msg = ""
    msg.lower().strip()
    print(Common.currentUser.get("name"))
    print(name_doc.lower())

    import requests
    if name_doc.lower().strip() != Common.currentUser.get("name").lower().strip():
        return render(req, 'doctument_page2.html',
                      {"user": Common.currentUser, "key": key,
                       "error": "Name as in documents do not match name in adhar card"})
    else:

        ministry_id = db.child("Service").child(str(key)).child("ministry").get().val()
        found = None
        try:
            found = db.child("Documents").child(str(ministry_id)).child(sname).child(cno).get().val()
        except:
            pass

        if found == None:
            return render(req, 'doctument_page2.html',
                          {"user": Common.currentUser, "key": key,
                           "error": "Document Not found"})
        else:
            responseimg = requests.get(req.POST['fileurl'])
            storage = connect_firebasesto()
            path = "tempuserdoc/" + str(Common.currentUser.get("aadharno"))
            # storage.child(path).download("download.pdf")
            storage.child("tempuserdoc/domicile.pdf").download("tempuserdoc/domicile.pdf", sname + ".pdf")
            generatedigitalsign(sname + ".pdf")
            storage.child("DigitalDoc/" + Common.currentUser.get('aadharno') + "/" + sname + "-signed.pdf").put(
                sname + "-signed.pdf")
            url = storage.child(
                "DigitalDoc/" + Common.currentUser.get('aadharno') + "/" + sname + "-signed.pdf").get_url(
                "123")

            data = {
                "sname": sname, "url": url
            }
            try:
                alldoc = db.child("userdoc").child(Common.currentUser.get("aadharno")).get().val()
            except:
                pass
            if alldoc == None:
                alldoc = []
            alldoc.append(data)

            db.child("userdoc").update({Common.currentUser.get("aadharno"): alldoc})

            # -------- GOV DATA

            storage.child("GOVDOC/" + Common.currentUser.get('aadharno') + "/" + sname + "-signed.pdf").put(
                sname + "-signed.pdf")
            url = storage.child("GOVDOC/" + Common.currentUser.get('aadharno') + "/" + sname + "-signed.pdf").get_url(
                "123")

            data = {
                "sname": sname, "url": url
            }
            try:
                alldoc = db.child("GOVDOC").child(Common.currentUser.get("aadharno")).get().val()
            except:
                pass
            if alldoc == None:
                alldoc = []
            alldoc.append(data)

            db.child("GOVDOC").update({Common.currentUser.get("aadharno"): alldoc})

        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Done",
                       "path": "issue_doc"})


def issue_doc(req):
    db = connect_firebase()
    alldoc = None
    try:
        alldoc = db.child("userdoc").child("335179014426").get().val()
        # alldoc = db.child("userdoc").child(Common.currentUser.get("aadharno")).get().val()
    except:
        pass

    print(alldoc)

    return render(req, 'issued_document.html',
                  {"user": Common.currentUser, "alldoc": alldoc}
                  )


def autofill(req, pk):
    from PIL import Image
    import requests
    from io import BytesIO

    response = requests.get(req.POST['fileurl'])
    key = req.POST['key']

    print(req.POST['fileurl'])
    image_path_in_colab = Image.open(BytesIO(response.content))

    # image_path_in_colab="https://i.ytimg.com/vi/zJFHOJDIX30/maxresdefault.jpg"
    # extractedInformation = pytesseract.image_to_string(Image.open(image_path_in_colab))
    extractedInformation = pytesseract.image_to_string(image_path_in_colab)
    print(extractedInformation)
    import re
    found = " "
    m = re.search('SR\.NO\.(.+?)\.', extractedInformation)
    if m:
        found = m.group(1)
        print(found, " matches")
    m1name = re.search('Shri\.(.+?),', extractedInformation)
    if m1name:
        foundname = m1name.group(1)
        print(foundname, " matches")
    db = connect_firebase()
    servicedetails = db.child("Service").child(str(pk)).get().val()
    return render(req, 'doctument_page2.html',
                  {"user": Common.currentUser, "servicedetails": servicedetails, "foundsrno":
                      found, "extractedInformation": extractedInformation, "urllink": req.POST['fileurl'],
                   "foundname": foundname, "key": key}
                  )


def addusertodb(request):
    passw = request.POST['pass']
    db = connect_firebase()
    db.child("users").child(Common.tempuser.get("aadharno")).update(Common.tempuser)
    db.child("users").child(Common.tempuser.get("aadharno")).update(
        {"password": passw, "enckey": Fernet.generate_key().decode()})

    return render(request, 'redirecthome.html',
                  {"swicon": "success", "swtitle": "Done", "swmsg": "Registration Successfully.",
                   "path": "login"})


def updatepassword(request):
    new_password = request.POST['pass']
    db = connect_firebase()

    db.child("users").child(Common.userphone).child("password").set(
        new_password
    )

    return render(request, 'redirecthome.html',
                  {"swicon": "success", "swtitle": "Done", "swmsg": "Password Changed Successfully.",
                   "path": "login"})


def verify(request):
    if not Common.isLogin:
        aadharno = request.POST.get('aadharno')
        password = request.POST.get('password')

        db = connect_firebase()
        user = db.child("users").child(aadharno).get().val()

        if not user:
            return render(request, 'redirecthome.html',
                          {"swicon": "error", "swtitle": "Error", "swmsg": "User does not exists", "path": "login"})
        elif password == user.get("password"):
            Common.currentUser = user
            Common.isLogin = True

            return HttpResponseRedirect('/userdashboard')
        else:
            return render(request, 'redirecthome.html',
                          {"swicon": "error", "swtitle": "Error", "swmsg": "Invalid Password",
                           "path": "login"})
    else:
        return HttpResponseRedirect('/')


def userdashboard(req):
    db = connect_firebase()
    ministry = db.child("Ministry").get().val()
    return render(req, 'ministries.html',
                  {"user": Common.currentUser, "ministry": ministry})


def getallservices(req, pk):
    db = connect_firebase()
    allservice = None
    try:
        allservice = db.child("Service").order_by_child("ministry").equal_to(str(pk)).get().val()
    except:
        pass
    return render(req, 'ministries_service.html', {"user": Common.currentUser, "service": allservice})


def getservice(req, pk):
    db = connect_firebase()
    servicedetails = db.child("Service").child(str(pk)).get().val()
    return render(req, 'doctument_page.html',
                  {"user": Common.currentUser, "servicedetails": servicedetails, "key": str(pk)})


def trust_verify(request):
    if not Common.isTrustLogin:
        trustusername = request.POST.get('trust_username')
        password = request.POST.get('password')

        print(password)
        db = connect_firebase()
        trust = None
        try:
            user = db.child("Trust").order_by_child("mailid").equal_to(trustusername).get().val()

            for key, value in user.items():
                trustkey = key
                trust = value
        except:
            pass

        if trust == None:
            return render(request, 'redirecthome.html',
                          {"swicon": "error", "swtitle": "Error", "swmsg": "Invalid Trust Id", "path": "trustlogin"})
        elif password == trust.get("password"):
            Common.trustkey = trustkey
            Common.trustVal = trust
            Common.isTrustLogin = True
            return HttpResponseRedirect('/trusthome')
        else:
            return render(request, 'redirecthome.html',
                          {"swicon": "error", "swtitle": "Error", "swmsg": "Invalid Password",
                           "path": "trustlogin"})
    else:
        c = {'user': Common.currentUser.val()}
        return HttpResponseRedirect('/')


def trust_home(req):
    if (Common.isTrustLogin):
        data = OrderedDict()

        db = connect_firebase()
        try:
            data = db.child("AppliedScheme").order_by_child("trust_id").equal_to(
                Common.trustkey).get().val()
            data = collections.OrderedDict(reversed(list(data.items())))
        except:
            pass

        print(data)
        return render(req, 'trust_home.html',
                      {"trustkey": Common.trustkey, "trust_val": Common.trustVal, "applied_schemes": data})
    else:
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def viewtakeaction(request):
    userphone = request.POST['userphone']
    applicationid = request.POST['applicationid']

    if (Common.isTrustLogin):

        db = connect_firebase()
        applied = OrderedDict()
        amount_received = 0
        application = db.child("AppliedScheme").child(applicationid).get().val()
        userprofile = db.child("UserProfile").child(userphone).get().val()
        cipher = Fernet(Common.encyptionkey)
        accno = cipher.decrypt(userprofile.get("account_number").encode()).decode()
        pendingamt = int(userprofile.get("coursefees"))
        schemeeligibility = db.child("Scheme").child(application.get("scheme_id")).child("eligibility").get().val()

        userappliedscholarship = db.child("AppliedScheme").order_by_child("userid").equal_to(
            userphone).get().val()
        del userappliedscholarship[applicationid]
        print(userappliedscholarship)

        for key, value in userappliedscholarship.items():
            print(key, "is ", value.get("status"))
            if value.get("status") == "Approve":
                print(value, "is approve")
                amount_received += int(value.get("sanctionedamount"))
                tmp = {key: value}
                applied.update(tmp)
                print(applied)
        pendingamt = pendingamt - amount_received
        return render(request, 'trust_takeaction.html',
                      {"trustkey": Common.trustkey, "trust_val": Common.trustVal,
                       "application": application, "applicationid": applicationid,
                       "userprofile": userprofile, "accno": accno, "appliedscholarship": applied,
                       "amtrec": str(amount_received), "amtpen": str(pendingamt), "schemeeligibility": schemeeligibility

                       })
    else:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def updateapplicationstatus(request):
    if (Common.isTrustLogin):
        applicationid = request.POST['applicationid']
        status = request.POST['status']
        interviewdate = request.POST['interviewdate']
        sancamt = request.POST['sancamt']
        remark = request.POST['remark']
        mail = request.POST['mail']
        schemename = request.POST['schemename']

        data = {
            "interviewdate": interviewdate, "status": status, "sanctionedamount": sancamt,
            "remark": remark
        }
        db = connect_firebase()
        db.child("AppliedScheme").child(applicationid).update(data)

        title = "ScholarHelp - Status updated fo applicatiod id " + applicationid
        msg = "Your application status for " + schemename + " has been updated to " + status + ".Please login to " \
                                                                                               "ScholarHelp to view " \
                                                                                               "more details. "
        print(msg)
        sendmail(mail, title, msg)
        return render(request, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Application Status Updated Successfully",
                       "path": "trusthome"})

    else:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def viewtrustprofile(request):
    db = connect_firebase()
    Common.trustVal = db.child("Trust").child(Common.trustkey).get().val()

    return render(request, 'trust_profile.html',
                  {"trustkey": Common.trustkey, "trust_val": Common.trustVal})


def updatetrustprofile(request):
    if (Common.isTrustLogin):
        tname = request.POST['tname']
        tcontact = request.POST['tcontact']
        temailid = request.POST['temailid']
        tabout = request.POST['tabout']
        taddress = request.POST['taddress']
        tvision = request.POST['tvision']
        tpass = request.POST['tpass']

        data = {
            "name": tname, "contact": tcontact, "mailid": temailid,
            "about": tabout, "address": taddress, "vision": tvision, "password": tpass
        }
        db = connect_firebase()
        db.child("Trust").child(Common.trustkey).update(data)

        return render(request, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Profile Updated Successfully",
                       "path": "trusthome"})

    else:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def addscholarhip(req):
    if (Common.isTrustLogin):
        return render(req, 'add_scholarship.html',
                      {"trustkey": Common.trustkey, "trust_val": Common.trustVal})
    else:
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": ""})


def viewallscholarships(request):
    schemes = OrderedDict()
    db = connect_firebase()
    try:
        schemes = db.child("Scheme").order_by_child("trust_id").equal_to(Common.trustkey).get().val()
    except:
        print("Error")
    return render(request, 'trust_allscheme.html',
                  {"trustkey": Common.trustkey, "trust_val": Common.trustVal,
                   "scholarships": schemes
                   })


def register(request):
    return render(request, 'register.html', {})


def trust_logout(request):
    Common.trustkey = None
    Common.trustVal = None
    Common.isTrustLogin = False
    Common.isLogin = False

    return render(request, 'redirecthome.html',
                  {"swicon": "success", "swtitle": "Done", "swmsg": "Logout Successfully", "path": ""})


def adminlogout(request):
    Common.isAdminLogin = False

    return render(request, 'redirecthome.html',
                  {"swicon": "success", "swtitle": "Done", "swmsg": "Logout Successfully", "path": ""})


def logout(request):
    Common.currentUser = None
    Common.isLogin = False
    return render(request, 'redirecthome.html',
                  {"swicon": "success", "swtitle": "Done", "swmsg": "Logout Successfully", "path": ""})


def adduser(req):
    name = req.POST['name']
    email = req.POST['email']
    phone = req.POST['phone']
    passwrd = req.POST['pass']
    useremail = None
    db = connect_firebase()

    user = db.child("users").child(phone).get()
    try:
        useremail = db.child("users").order_by_child("mail").equal_to(email).get().val()
    except:
        pass
    print(useremail)
    if user.val():
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "User Already Exists", "path": "register"})
    elif useremail:
        return render(req, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "User Mail Exists", "path": "register"})
    else:
        data = {
            "name": name, "mail": email, "password": passwrd, "phone": phone, "profilefill": "0"
        }
        db.child("users").child(phone).set(data)

        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Registration Done Successfully.",
                       "path": "login"})


def updatescholarhiptofire(req):
    sname = req.POST['sname']
    samt = req.POST['samt']
    scourse = req.POST['scoursename']
    scat = req.POST['scat']
    seligibility = req.POST['seligibility']

    key = req.POST['key']
    strdead = 'sdeadline-' + key
    sdeadline = req.POST[strdead]
    logo = Common.trustVal.get("logo")
    trust_id = Common.trustkey
    db = connect_firebase()

    data = {
        "amount": samt, "course": scourse, "eligibility": seligibility, "lastdate": sdeadline,
        "level": scat, "logo": logo, "name": sname, "trust_id": trust_id
    }

    db.child("Scheme").child(key).update(
        data
    )

    return render(req, 'redirecthome.html',
                  {"swicon": "success", "swtitle": "Done", "swmsg": "Scholarhip Updated Successfully.",
                   "path": "trusthome"})


def addscholarhiptofire(req):
    sname = req.POST['sname']
    samt = req.POST['samt']
    scourse = req.POST['scoursename']
    scat = req.POST['scat']
    seligibility = req.POST['seligibility']
    sdeadline = req.POST['sdeadline']
    timestamp = datetime.timestamp(datetime.now())
    logo = Common.trustVal.get("logo")
    trust_id = Common.trustkey
    db = connect_firebase()

    data = {
        "amount": samt, "course": scourse, "eligibility": seligibility, "lastdate": sdeadline,
        "level": scat, "logo": logo, "name": sname, "trust_id": trust_id
    }
    print(str(timestamp))

    strtimestamp = str(timestamp).replace('.', '')

    db.child("Scheme").child(strtimestamp[:13]).set(
        data
    )

    return render(req, 'redirecthome.html',
                  {"swicon": "success", "swtitle": "Done", "swmsg": "Scholarship Added Successfully.",
                   "path": "trusthome"})


def viewtrustdetails(request, pk):
    global schemes
    schemes = OrderedDict()
    db = connect_firebase()
    trust = db.child("Trust").child(str(pk)).get().val()
    all_trusts = db.child("Trust").order_by_key().get().val()
    del all_trusts[str(pk)]
    try:
        schemes = db.child("Scheme").order_by_child("trust_id").equal_to(str(pk)).get().val()
    except:
        print("Error")

    return render(request, 'trustdetails.html',
                  {"scheme": schemes, 'trust': trust, "all_trusts": all_trusts, "islog": Common.isLogin
                   })


def schemedetail(req, pk):
    db = connect_firebase()
    scheme = db.child("Scheme").child(str(pk)).get().val()
    isclosed = False
    print(scheme.get("lastdate"))
    deadline = datetime.strptime(scheme.get("lastdate"), "%d-%B-%Y")
    today = datetime.now()
    if deadline < today:
        isclosed = True
    db = connect_firebase()
    alldoc = None
    try:
        alldoc = db.child("userdoc").child("335179014426").get().val()
        # alldoc = db.child("userdoc").child(Common.currentUser.get("aadharno")).get().val()
    except:
        pass

    return render(req, 'schemedet.html',
                  {"scheme": scheme, "isclosed": isclosed,
                   "alldoc": alldoc
                   })


def userapply(req):
    applicationid = datetime.timestamp(datetime.now())
    applicationid = str(applicationid).replace('.', '')
    applicationid = applicationid[:13]
    mail = Common.currentUser.get("mail")
    sendmail(mail, "Successfully Applied",
             "Your have success fully applied for Scheme. Your application is " + applicationid)

    return render(req, 'redirecthome.html',
                  {"swicon": "Suceess", "swtitle": "Done", "swmsg": "Your Application id is " + applicationid,
                   "path": "userdashboard"})


def viewschemedetails(request, pk):
    global schemes
    db = connect_firebase()
    #
    # all_trusts = db.child("Trust").order_by_key().get().val()
    # del all_trusts[str(pk)]
    applied_scheme = None
    try:

        applied_scheme = Common.currentUser.val().get("applied_scheme")
    except:
        pass
    if applied_scheme == None:
        applied_scheme = []
    isapply = "False"
    if str(pk) in applied_scheme:
        isapply = "True"
    scheme = db.child("Scheme").child(str(pk)).get().val()
    trust = db.child("Trust").child(scheme.get("trust_id")).get().val()
    other_schemes = db.child("Scheme").order_by_child("level").equal_to(scheme.get("level")).get().val()
    del other_schemes[str(pk)]
    isclosed = False
    print(scheme.get("lastdate"))
    deadline = datetime.strptime(scheme.get("lastdate"), "%d-%B-%Y")
    today = datetime.now()
    if deadline < today:
        isclosed = True

    return render(request, 'schemedetails.html',
                  {"scheme": scheme, 'trust': trust,
                   "other_schemes": other_schemes, "islog": Common.isLogin, "scheme_key": str(pk),
                   "isapply": isapply, "isclosed": isclosed

                   })


# User Profiles#
def profile_personalDetails(request):
    if (Common.isLogin):
        userprofile = OrderedDict()

        db = connect_firebase()
        accno = ""
        Common.currentUser = db.child("users").child(Common.currentUser.val().get("phone")).get()
        try:
            userprofile = db.child("UserProfile").child(Common.currentUser.val().get("phone")).get().val()
            cipher = Fernet(Common.encyptionkey)
            accno = cipher.decrypt(userprofile.get("account_number").encode()).decode()
        except:
            print("Error")

        if (Common.currentUser.val().get("profilefill") != "100"):
            return render(request, 'user_profileDetails.html',
                          {"userprofile": userprofile, "currentuser": Common.currentUser.val(), "accno": accno})
        else:
            return render(request, 'user_completeprofile.html',
                          {"userprofile": userprofile, "currentuser": Common.currentUser.val(), "accno": accno
                           })

    else:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": "login"})


def profile_familyDetails(request):
    if (Common.isLogin):
        userprofile = OrderedDict()

        db = connect_firebase()

        Common.currentUser = db.child("users").child(Common.currentUser.val().get("phone")).get()
        try:
            userprofile = db.child("UserProfile").child(Common.currentUser.val().get("phone")).get().val()
        except:
            print("Error")

        if (Common.currentUser.val().get("profilefill") != "100"):
            return render(request, 'user_familyDetails.html',
                          {"userprofile": userprofile, "currentuser": Common.currentUser.val()})
        else:
            return render(request, 'user_completeprofile.html',
                          {"userprofile": userprofile, "currentuser": Common.currentUser.val(),
                           })
    else:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": "login"})


def profile_education(request):
    if (Common.isLogin):
        userprofile = OrderedDict()

        db = connect_firebase()

        Common.currentUser = db.child("users").child(Common.currentUser.val().get("phone")).get()
        try:
            userprofile = db.child("UserProfile").child(Common.currentUser.val().get("phone")).get().val()
        except:
            print("Error")

        if (Common.currentUser.val().get("profilefill") != "100"):
            return render(request, 'user_education.html',
                          {"userprofile": userprofile, "currentuser": Common.currentUser.val()})
        else:
            return render(request, 'redirecthome.html',
                          {"swicon": "error", "swtitle": "Profile Submitted", "swmsg": "You cant change any details",
                           "path": ""})

    else:
        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": "login"})


def profile_doc(request):
    if (Common.isLogin):
        userprofile = OrderedDict()

        db = connect_firebase()

        Common.currentUser = db.child("users").child(Common.currentUser.val().get("phone")).get()
        try:
            userprofile = db.child("UserProfile").child(Common.currentUser.val().get("phone")).get().val()
        except:
            print("Error")

        if (Common.currentUser.val().get("profilefill") != "100"):
            return render(request, 'user_doc.html',
                          {"userprofile": userprofile, "currentuser": Common.currentUser.val(),
                           "config": PyConfig.config1})
        else:
            return render(request, 'user_completeprofile.html',
                          {"userprofile": userprofile, "currentuser": Common.currentUser.val(),
                           })
    else:

        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": "login"})


def saveuserpersonalinfo(req):
    surname = req.POST['sname']
    first_name = req.POST['fname']
    last_name = req.POST['lname']
    dob = req.POST['dob']
    age = req.POST['age1']
    gender = req.POST['gender']

    email = req.POST['email']
    phone = req.POST['phone']
    parent_phone = req.POST['parent_phone']

    religious = req.POST['religious']
    cast = req.POST['cast']
    annual_income = req.POST['anual_income']

    nameinpassbook = req.POST['nameinpassbook']
    account_number = req.POST['account_number']
    bank_name = req.POST['bank_name']
    ifsc_code = req.POST['ifsc_code']
    fill = req.POST['fill']
    save_draft = req.POST['saveasdraft']

    db = connect_firebase()
    data = dict()
    try:
        data = db.child("UserProfile").child(Common.currentUser.val().get("phone")).get().val()
        data = dict(data)
    except:
        pass
    if data == None:
        data = dict()

    cipher = Fernet(Common.encyptionkey)
    encaccountnum = cipher.encrypt(account_number.encode())
    print(encaccountnum)

    newdata = {
        "sname": surname, "fname": first_name, "lname": last_name, "dob": dob, "age": age, "gender": gender,
        "email": email, "phone": phone, "parent_phone": parent_phone,
        "religious": religious, "cast": cast, "annual_income": annual_income,
        "account_number": encaccountnum.decode(), "bank_name": bank_name, "ifsc_code": ifsc_code.upper(),
        "nameinpassbook": nameinpassbook

    }

    data.update(newdata)
    print(data)
    db.child("UserProfile").child(str(phone)).set(
        data
    )

    db.child("users").child(str(phone)).child("profilefill").set(fill)
    if save_draft == "1":
        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Personal Details Saved Successfully.",
                       "path": ""})
    if save_draft == "0":
        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Personal Details Saved Successfully.",
                       "path": "profile-familyDetails"})


def saveuserfamilyinfo(req):
    address = req.POST['address']
    pincode = req.POST['pincode']

    fatheralive = req.POST['fatheralive']
    fathername = req.POST['fathername']
    fatheroccupation = req.POST['father_occupation']
    fatherincome = req.POST['father_income']

    motheralive = req.POST['motheralive']
    mothername = req.POST['mothername']
    motheroccupation = req.POST['mother_occupation']
    motherincome = req.POST['mother_income']

    fill = req.POST['fill']
    save_draft = req.POST['saveasdraft']

    db = connect_firebase()

    data = db.child("UserProfile").child(Common.currentUser.val().get("phone")).get().val()
    data = dict(data)
    print(data)
    newdata = {
        "address": address, "pincode": pincode,
        "fatheralive": fatheralive, "fathername": fathername, "fatheroccupation": fatheroccupation,
        "fatherincome": fatherincome,
        "motheralive": motheralive, "mothername": mothername, "motheroccupation": motheroccupation,
        "motherincome": motherincome
    }

    data.update(newdata)
    print(data)
    db.child("UserProfile").child(Common.currentUser.val().get("phone")).set(
        data
    )

    db.child("users").child(Common.currentUser.val().get("phone")).child("profilefill").set(fill)
    if save_draft == "1":
        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Family Details Saved Successfully.",
                       "path": ""})
    if save_draft == "0":
        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Family Details Saved Successfully.",
                       "path": "profile-education"})


def saveusereducation(req):
    collegename = req.POST['collegename']
    collegeaddress = req.POST['collegeaddress']

    coursename = req.POST['coursename']
    coursefees = req.POST['coursefees']

    course1name = req.POST['course1name']
    course1year = req.POST['course1year']
    course1board = req.POST['course1board']
    course1per = req.POST['course1per']

    course2name = req.POST['course2name']
    course2year = req.POST['course2year']
    course2board = req.POST['course2board']
    course2per = req.POST['course2per']

    course3name = req.POST['course3name']
    course3year = req.POST['course3year']
    course3board = req.POST['course3board']
    course3per = req.POST['course3per']

    achievement = req.POST['achievement']

    fill = req.POST['fill']
    save_draft = req.POST['saveasdraft']

    db = connect_firebase()

    data = db.child("UserProfile").child(Common.currentUser.val().get("phone")).get().val()
    data = dict(data)
    print(data)
    newdata = {
        "collegename": collegename, "collegeaddress": collegeaddress, "coursename": coursename,
        "coursefees": coursefees,
        "course1name": course1name, "course1board": course1board, "course1year": course1year, "course1per": course1per,
        "course2name": course2name, "course2board": course2board, "course2year": course2year, "course2per": course2per,
        "course3name": course3name, "course3board": course3board, "course3year": course3year, "course3per": course3per,
        "achievement": achievement
    }

    data.update(newdata)
    print(data)
    db.child("UserProfile").child(Common.currentUser.val().get("phone")).set(
        data
    )

    db.child("users").child(Common.currentUser.val().get("phone")).child("profilefill").set(fill)
    if save_draft == "1":
        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Education Details Saved Successfully.",
                       "path": ""})
    if save_draft == "0":
        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Education Details Saved Successfully.",
                       "path": "profile-uploaddoc"})


def savedocuments(req):
    docphotoidname = req.POST['docphotoidname']
    docageproofname = req.POST['docageproofname']

    docadmissionname = req.POST['docadmissionname']
    doccurrentfeename = req.POST['doccurrentfeename']

    docaddressname = req.POST['docaddressname']
    docincomename = req.POST['docincomename']

    docphotoidurl = req.POST['docphotoidurl']

    docageproofurl = req.POST['docageproofurl']

    docadmissionurl = req.POST['docadmissionurl']
    doccurrentfeeurl = req.POST['doccurrentfeeurl']
    docaddressurl = req.POST['docaddressurl']
    docincomeurl = req.POST['docincomeurl']

    doccourse1url = req.POST['doccourse1url']
    doccourse2url = req.POST['doccourse2url']
    doccourse3url = req.POST['doccourse3url']
    docpassbookurl = req.POST['docpassbookurl']

    fill = req.POST['fill']
    save_draft = req.POST['saveasdraft']

    db = connect_firebase()

    data = db.child("UserProfile").child(Common.currentUser.val().get("phone")).get().val()
    data = dict(data)
    print(data)
    newdata = {
        "docphotoidname": docphotoidname, "docageproofname": docageproofname, "docadmissionname": docadmissionname,
        "doccurrentfeename": doccurrentfeename, "docaddressname": docaddressname, "docincomename": docincomename,
        "docphotoidurl": docphotoidurl, "docageproofurl": docageproofurl, "docadmissionurl": docadmissionurl,
        "doccurrentfeeurl": doccurrentfeeurl,
        "docaddressurl": docaddressurl, "docincomeurl": docincomeurl, "doccourse1url": doccourse1url,
        "doccourse2url": doccourse2url, "doccourse3url": doccourse3url, "docpassbookurl": docpassbookurl
    }

    data.update(newdata)
    print(data)
    db.child("UserProfile").child(Common.currentUser.val().get("phone")).set(
        data
    )

    db.child("users").child(Common.currentUser.val().get("phone")).child("profilefill").set(fill)
    if save_draft == "1":
        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Documents Saved Successfully.",
                       "path": ""})
    if save_draft == "0":
        return render(req, 'redirecthome.html',
                      {"swicon": "success", "swtitle": "Done", "swmsg": "Profile Submitted Successfully.",
                       "path": "user-completeprofile"})


def user_completeprofile(request):
    if (Common.isLogin):
        userprofile = OrderedDict()

        db = connect_firebase()

        Common.currentUser = db.child("users").child(Common.currentUser.val().get("phone")).get()
        try:
            userprofile = db.child("UserProfile").child(Common.currentUser.val().get("phone")).get().val()
        except:
            print("Error")

        if Common.currentUser.val().get("profilefill") == "100":
            return render(request, 'user_completeprofile.html',
                          {"userprofile": userprofile, "currentuser": Common.currentUser.val(),
                           })
        else:
            return render(request, 'redirecthome.html',
                          {"swicon": "error", "swtitle": "Profile Not Submitted", "swmsg": "Please Complete profile",
                           "path": ""})
    else:

        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": "login"})


# Apply for scheme/scholarship

def applyscholarship(request):  # user has click on apply button add userinfo to db
    if (Common.isLogin):
        userprofile = OrderedDict()

        db = connect_firebase()

        Common.currentUser = db.child("users").child(Common.currentUser.val().get("phone")).get()
        try:
            userprofile = db.child("UserProfile").child(Common.currentUser.val().get("phone")).get().val()
        except:
            print("Error")

        if Common.currentUser.val().get("profilefill") == "100":

            schemeid = request.POST['schemeid_apply']
            amount = request.POST['amount']
            trust_id = request.POST['trust_id']
            schemename = request.POST['schemename']

            userphone = Common.currentUser.val().get("phone")
            name = userprofile.get("sname") + " " + userprofile.get("fname") + " " + userprofile.get("lname")
            status = "Pending"

            applicationid = datetime.timestamp(datetime.now())
            applicationid = str(applicationid).replace('.', '')
            applicationid = applicationid[:13]

            tname = db.child("Trust").child(trust_id).child("name").get().val()
            print(tname)

            data = {
                "userid": userphone, "username": name,
                "scheme_id": schemeid, "scheme_name": schemename, "schemeamount": amount,
                "status": status, "remark": "", "sanctionedamount": "0", "trust_id": trust_id, "tname": tname
            }

            db.child("AppliedScheme").child(applicationid).set(
                data
            )

            applied_scheme = None
            try:

                print(Common.currentUser.val())
                applied_scheme = Common.currentUser.val().get("applied_scheme")

                print(Common.currentUser.val())
                print("inside try" + applied_scheme)
            except:
                pass
            if applied_scheme == None:
                applied_scheme = []
            print(applied_scheme)
            applied_scheme.append(schemeid)

            db.child("users").child(userphone).update(
                {"applied_scheme": applied_scheme}
            )

            return render(request, 'redirecthome.html',
                          {"swicon": "success", "swtitle": "Done",
                           "swmsg": "Applied Successfully. Your Application number is " + applicationid,
                           "path": "appliedscholarship"})
        else:
            return render(request, 'redirecthome.html',
                          {"swicon": "error", "swtitle": "Profile Not Submitted", "swmsg": "Please Complete profile",
                           "path": "profile-personalDetails"})
    else:

        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": "login"})


def appliedscholarship(request):
    if (Common.isLogin):
        data = OrderedDict()

        db = connect_firebase()
        try:
            data = db.child("AppliedScheme").order_by_child("userid").equal_to(
                Common.currentUser.val().get("phone")).get().val()
        except:
            pass

        return render(request, 'user_appliedscheme.html',
                      {"currentuser": Common.currentUser.val(), "applied_schemes": data})
    else:

        return render(request, 'redirecthome.html',
                      {"swicon": "error", "swtitle": "Error", "swmsg": "Please try again", "path": "login"})
