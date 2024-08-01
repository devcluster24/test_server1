from django.urls import path
from apps.websiteInformation.views import (
                                            AboutCreateView,
                                            AboutListView,
                                            AboutRetrieveUpdateDestroyViews,
                                            ContactCreateView,
                                            ContactListView,
                                            ContactRetrieveUpdateDestroyViews,
                                            NewsLetterCreateView, NewsLetterListView,
                                            NewsLetterRetrieveUpdateDestroyViews
                                          )


urlpatterns = [
    path('about/', AboutCreateView.as_view(), name='create_about'),
    path('about/list/', AboutListView.as_view(), name='about_data'),
    path('about/<int:pk>/', AboutRetrieveUpdateDestroyViews.as_view(), name='about_detail'),
    path('contact/', ContactCreateView.as_view(), name='create_contact'),
    path('contact/list/', ContactListView.as_view(), name='contact_data'),
    path('contact/<int:pk>/', ContactRetrieveUpdateDestroyViews.as_view(), name='contact_detail'),
    path('newsletter/', NewsLetterCreateView.as_view(), name='create_newsletter'),
    path('newsletter/list/', NewsLetterListView.as_view(), name='newsletter_data'),
    path('newsletter/<int:pk>/', NewsLetterRetrieveUpdateDestroyViews.as_view(), name='newsletter_detail'),
]
