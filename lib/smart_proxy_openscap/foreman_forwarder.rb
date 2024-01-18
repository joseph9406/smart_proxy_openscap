require 'smart_proxy_openscap/openscap_exception'

module Proxy::OpenSCAP
  class ForemanForwarder < Proxy::HttpRequest::ForemanRequest
    include ::Proxy::Log

    def post_report(cname, policy_id, date, data, timeout) 
      foreman_api_path = report_upload_path(cname, policy_id, date)  # 目標服務器的path, report_upload_path方法的內容要在此類的子類中來實現      
      json = parse_report(cname, policy_id, date, data)  # 将想要上傳的报告数据解析为 JSON 格式。
      response = send_request(foreman_api_path, json, timeout)      
      
      #***** response.value 是 Net::HTTPResponse 类的一个方法，用于检查 HTTP 响应的状态码是否表示成功。*****
      # 具体而言，如果响应的状态码在 200 到 299 的范围内（2xx 表示成功），则 response.value 不做任何事情；
      # 否则，它会抛出 Net::HTTPServerException 异常。
      # 这样的设计可以让你在处理 HTTP 响应之前先确保它是成功的，从而更好地控制程序的行为。
      response.value
      # 服务器返回的原始数据，通常是一个字符串。这个字符串的内容取决于服务器返回的内容类型（Content-Type）。
      # 如果服务器在响应头中设置了 Content-Type: application/json，那么 response.body 中的数据就很可能是 JSON 格式的字符串。
      # 那又為什麼服務器要返回 json 格式的 response.body 呢? 因為是客戶端在發送請求時,要求服務器用 json 格式回應。
      JSON.parse(response.body)  # 将 JSON 字符串解析为 Ruby 对象,
    rescue Net::HTTPServerException => e
      logger.debug "Received response: #{response.code} #{response.msg}"
      logger.debug response.body
      raise ReportUploadError, e.message if response.code.to_i == 422
      raise e
    end

    private

    def upload_path(resource, cname, policy_id, date)
      "/api/v2/compliance/#{resource}/#{cname}/#{policy_id}/#{date}"
    end

    def parse_report(cname, policy_id, date, data)
      raise NotImplementedError
    end

    # 方法中的 uri、http 是從父類 Proxy::HttpRequest::ForemanRequest 繼承得來的
    def send_request(path, body, timeout)
      # Override the parent method to set the right headers
      path = [uri.path, path].join('/') unless uri.path.empty?  # 将 uri.path 和 path 以 / 分隔连接在一起。
      # uri.to_s = "http://example.com/path/to/resource"; path = "/aaa/bbb"; 
      # 因為path是絶對路徑,所以, path 會取代整個 "/path/to/resource", 結果是 URI.join(uri.to_s, path)是"http://example.com/aaa/bbb" 
      req = Net::HTTP::Post.new(URI.join(uri.to_s, path).path) 
      req.add_field('Accept', 'application/json,version=2')    # 'Accept' 表明客户端期望服務器回傳的是 JSON 格式的响应，
      req.content_type = 'application/json'  # 'Content-Type' 表明请求体的格式为 JSON。
      req.body = body  # 客戶端發送的post請求中帶的請求內容(因為是post,所以請求內容是放在body中)
      http.read_timeout = timeout if timeout
      http.request(req)  # 执行 HTTP POST 请求發送，并返回响应对象。
    end
  end
end
