"""Scholar_Help URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from django.urls import path

from . import views

# from Scholar_Help.views import home, login, register

urlpatterns = [
    path('admin/', admin.site.urls),
    url(r'^trust/(?P<pk>\d+)$', views.viewtrustdetails),
    url(r'^scheme/(?P<pk>\d+)$', views.viewschemedetails),
    url(r'^schemedetails/(?P<pk>\d+)$', views.schemedetail),
    url(r'^getcat([?^/*])', views.category),

    path('login/', views.login),
    path('userapply/', views.userapply),
    path('logout/', views.logout),
    path('uplaoded_doc/', views.uplaoded_doc),
    path('pending_doc/', views.pending_doc),

    path('trustlogin/', views.trust_login),
    path('applyscheme/', views.applyscheme),
    path('trustverify', views.trust_verify),
    path('trusthome/', views.trust_home),
    path('trustlogout/', views.trust_logout),
    path('addscholarhip/', views.addscholarhip),
    path('addscholarhiptofire', views.addscholarhiptofire),
    path('takeaction', views.viewtakeaction),
    path('updateapplicationstatus', views.updateapplicationstatus),
    path('view-allscholarships/', views.viewallscholarships),
    path('updatescholarhiptofire', views.updatescholarhiptofire),
    path('view-profile', views.viewtrustprofile),
    path('update-profile', views.updatetrustprofile),

    path('register/', views.register),
    path('verify', views.verify),
    path('adduser', views.adduser),

    path('user-aadhar-reg/', views.user_aadhar_reg),
    path('sendotp', views.sendotp),
    path('verifyotp/', views.verifyotp),
    path('checkotp', views.checkotp),
    path('user-reg', views.user_reg),
    path('addusertodb', views.addusertodb),
    path('userdashboard', views.userdashboard),
    path('runmlalgo', views.runmlalgo),
    path('validatedoc', views.validatedoc),
    path('issue_doc', views.issue_doc),
    url(r'^ministry/(?P<pk>\d+)$', views.getallservices),
    url(r'^services/(?P<pk>\d+)$', views.getservice),
    url(r'^autofill/(?P<pk>\d+)$', views.autofill),

    path('changepassword/', views.changepassword),
    path('updatepassword', views.updatepassword),
    # -----------------------------------------------------------------------
    path('profile-personalDetails', views.profile_personalDetails),
    path('saveuserpersonalinfo', views.saveuserpersonalinfo),
    path('profile-familyDetails', views.profile_familyDetails),
    path('saveuserfamilyinfo', views.saveuserfamilyinfo),
    path('profile-education', views.profile_education),
    path('saveusereducation', views.saveusereducation),
    path('profile-uploaddoc', views.profile_doc),
    path('saveuserdocuments', views.savedocuments),
    path('user-completeprofile', views.user_completeprofile),

    path('applyscholarship', views.applyscholarship),
    path('appliedscholarship/', views.appliedscholarship),

    path('admin-login/', views.adminlogin),
    path('adminverify', views.adminverify),
    path('adminhome/', views.adminhome),
    path('addtrust/', views.addtrust),
    path('addtrustdb', views.addtrustdb),
    path('adminupdatetrust', views.adminupdattrust),
    path('adminedittrust', views.adminedittrustview),
    path('admin_student', views.adminstudentview),
    path('studentprofile', views.studentprofile),
    path('removestudent', views.removestudent),
    path('removetrust', views.removetrust),

    path('adminlogout', views.adminlogout),
    path('test/', views.test),
    path('test1/', views.test1),
    path('userpro/', views.userpro),
    path('viewuserdoc', views.viewuserdoc),
    path('', views.login)
]
