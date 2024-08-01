from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class NewsPostPagination(PageNumberPagination):
    page_size = 7

    def get_paginated_response(self, data):
        return Response(data)