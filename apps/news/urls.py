from django.urls import path
from apps.news.views import (
                              NewsPostCreateViews,
                              NewsPostListApiViews,
                              NewsPostRetrieveUpdateDestroyApiViews,
                              NewsPostSearchFilterView,
                              CategoryCreateViews,
                              CategoryListView,
                              CategoryRetrieveUpdateDestroyApiViews,
                              LocationListViews,
                              LocationCreateViews,
                              LocationRetrieveUpdateDestroyApiViews,
                              LocationFilterView,
                              NewsPostFilterView,
                              AllNewsPostAdminViews     
                            )

urlpatterns = [
    path("list/", NewsPostListApiViews.as_view(), name='news_post'),
    path("", NewsPostCreateViews.as_view(), name='news_create'),
    path('<int:pk>/', NewsPostRetrieveUpdateDestroyApiViews.as_view(), name='post_detail'),
    path('searchfilter/', NewsPostSearchFilterView.as_view(), name='search-filter'),
    path("category/list/", CategoryListView.as_view(), name='category_list'),
    path("category/", CategoryCreateViews.as_view(), name='create_category'),
    path("category/<int:pk>/", CategoryRetrieveUpdateDestroyApiViews.as_view(), name='category_detail'),
    path("filter/", NewsPostFilterView.as_view(), name="filter-news"),
    path("location/filter/", LocationFilterView.as_view(), name='location-filter'),
    path("location/list/", LocationListViews.as_view(), name='location_list'),
    path("location/", LocationCreateViews.as_view(), name='location_create'),
    path("location/<int:pk>/", LocationRetrieveUpdateDestroyApiViews.as_view(), name='location_detail'),
]

