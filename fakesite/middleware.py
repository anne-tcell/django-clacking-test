class MyMiddleware:
    def process_response(self, request, response):
        response['Access-Control-Allow-Headers'] = "Access-Control-Allow-Origin, Accept, Accept-Encoding, Accept-Language, Access-Control-Request-Headers, Access-Control-Request-Method"
        return response

