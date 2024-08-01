from django.urls import path, include
from apps.account.views import (
                                UserRegistrationView, 
                                UserLoginView,
                                # UserLogoutView,
                                ActivateAccountView,
                                UserProfileView,
                                UserUpdateView,
                                AllUserView,
                                AllUserRetrieveUpdateDestroyView,
                                ChangePasswordView
                                )

urlpatterns = [
    path("admin/alluser/", AllUserView.as_view(), name='all-user'),
    path("admin/user/<int:pk>/", AllUserRetrieveUpdateDestroyView.as_view(), name="user_detail"),
    path('register/', UserRegistrationView.as_view(), name='registration'),
    path('login/', UserLoginView.as_view(), name='user_login'),
    # path('logout/', UserLogoutView.as_view(), name='user_logout'),
    path('active/<str:uid64>/<str:token>/', ActivateAccountView.as_view(), name='activate'),
    path('me/update/', UserUpdateView.as_view(), name='user-update'),
    path('me/', UserProfileView.as_view(), name='profile'),
    path('password/change/', ChangePasswordView.as_view(), name='password-change'),
    
]
