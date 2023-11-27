# """
# URL configuration for web_project project.

# The `urlpatterns` list routes URLs to views. For more information please see:
#     https://docs.djangoproject.com/en/4.2/topics/http/urls/
# Examples:
# Function views
#     1. Add an import:  from my_app import views
#     2. Add a URL to urlpatterns:  path('', views.home, name='home')
# Class-based views
#     1. Add an import:  from other_app.views import Home
#     2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
# Including another URLconf
#     1. Import the include() function: from django.urls import include, path
#     2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
# """
from django.contrib import admin
from django.urls import path, include
from yoyo_app import views
from django.urls import re_path
from yoyo_app.views import CustomTokenObtainPairView
# validation in API
#jei ivedi empty ar null tai api validation
#jei ivedi id kurio nera - tai not found , 300, 400 grazint turi
#per postman arba per django pati visus 15 komandu surasyt 

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", views.home, name="home"),
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('category/type/<str:type>/', views.get_cat_id, name="get_cat_id"),

    path('login/',views.login_user, name='login_user'),
    path('signup/',views.signup_user, name='signup_user'),

    
    path('latests/', views.get_latests, name='get_latests'),

    path('categories/', views.handle_category, name='handle_category'),
    path('categories/<int:pk>/', views.handle_category_id, name='handle_category_id'),

    path('categories/<int:cid>/tricks/', views.handle_trick, name='handle_trick'), 
    path('categories/<int:cid>/tricks/<int:tid>/', views.handle_trick_id, name='handle_trick_id'), 
    
    path('categories/<int:cid>/tricks/<int:tid>/comments/', views.handle_comment, name='handle_comment'),
    path('categories/<int:cid>/tricks/<int:tid>/comments/<int:ccid>/', views.handle_comment_id, name='handle_comment_id'),


]


    

    # /api/categories/{cid}/tricks/{trick}
    # path('tricks/create/', views.create_trick, name='create_trick'), # 201 created
    # path('tricks/<int:pk>/', views.get_trick, name='get_trick'), #200
    # path('tricks/edit/<int:pk>/', views.update_trick, name='update_trick'), #200
    # path('tricks/delete/<int:pk>/', views.delete_trick, name='delete_trick'), # 200/204
    # # re_path(r'^tricks/$', views.get_tricks_by_category, name='get_tricks_by_category'),


       # /api/categories/{cid}/tricks/{trick}/comments/{commentid}
    # path('comments/create/', views.create_comment, name='create_comment'),
    # path('comment/<int:comment_id>/', views.get_comment, name='get_comment'),
    # path('comments/<int:comment_id>/', views.get_comments, name='get_comments'),
    # path('comments/edit/<int:pk>/', views.update_comment, name='update_comment'),
    # path('comments/delete/<int:pk>/', views.delete_comment, name='delete_comment'),