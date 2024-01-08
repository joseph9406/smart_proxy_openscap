require 'openscap_parser/test_result_file'
require 'smart_proxy_openscap/openscap_exception'

module Proxy
  module OpenSCAP
    class ArfParser
      include Proxy::Log

      def initialize(cname, policy_id, date)
        @cname = cname
        @policy_id = policy_id
        @date = date
      end

      def as_json(arf_data)
        begin
          # 以下的作法是通过臨時文件,将数据传递给外部命令(因為外部命令 bunzip2 只能接受文件做為參數)。
          file = Tempfile.new   # 创建一个临时文件对象，该文件对象会在操作系统的临时目录中,生成一个唯一的文件名，并打开该文件以供写入。
          file.write(arf_data)  # 将 arf_data 写入临时文件中。这里假设 arf_data 是一个字符串或二进制数据。
          file.rewind           # 将文件指针（文件读写位置）移到文件的开头，以便后续读取文件内容。
          # 这行代码使用反引号（``）执行了一个 shell 命令
          # 因为 "OpenSCAP报告" 通常是经过压缩的（例如，使用 bzip2 压缩），需要解压缩以获取其中的内容。
          # -d: 解压缩, -c: 将解压缩的内容输出到标准输出。 将該文件解压缩後存储在 decompressed_data 变量中。
          decompressed_data = `bunzip2 -dc #{file.path}`  
        rescue => e
          logger.error e
          raise Proxy::OpenSCAP::ReportDecompressError, "Failed to decompress received report bzip, cause: #{e.message}"
        ensure
          file.close          
          file.unlink # 在Ruby中,由 Tempfile.new 創建的臨時文件會在程序退出時自動刪除。但是，若想在使用完临时文件後手动删除它，可以调用 unlink 刪除之。
        end
        arf_file = ::OpenscapParser::TestResultFile.new(decompressed_data)  # 用文本文件產生 Test Result 的"xml文件對象"。
        # reduce 和 inject 這兩個方法是一樣的,用于对集合（如数组）中的元素进行累积操作,返回最後累積的結果。
        # memo 一開始是一個空的hash,在迭代的過程中,一直向 memo 添加新的元素,最後, memo 包含了所有迭代的元素。
        rules = arf_file.benchmark.rules.reduce({}) do |memo, rule|  
          memo[rule.id] = rule
          memo  # 將這個 memo 做為這個block的返回值,賦值給rules
        end

        arf_digest = Digest::SHA256.hexdigest(arf_data)
        report = parse_results(rules, arf_file.test_result, arf_digest)
        report[:openscap_proxy_name] = Proxy::OpenSCAP::Plugin.settings.registered_proxy_name
        
        report[:openscap_proxy_url] = Proxy::OpenSCAP::Plugin.settings.registered_proxy_url
        report.to_json  # 将报告对象转换为 JSON 格式。
      end

      private

      def parse_results(rules, test_result, arf_digest)
        results = test_result.rule_results
        set_values = test_result.set_values
        report = {}
        report[:logs] = []
        passed = 0
        failed = 0
        othered = 0
        results.each do |result|
          next if result.result == 'notapplicable' || result.result == 'notselected'  # 跳过 notapplicable 和 notselected 类型的结果。
          # get rules and their results
          rule_data = rules[result.id]
          report[:logs] << populate_result_data(result.id, result.result, rule_data, set_values)
          # create metrics for the results
          case result.result
            when 'pass', 'fixed'
              passed += 1
            when 'fail'
              failed += 1
            else
              othered += 1
          end
        end
        report[:digest]  = arf_digest
        report[:metrics] = { :passed => passed, :failed => failed, :othered => othered }
        report[:score] = test_result.score
        report
      end

      def populate_result_data(result_id, rule_result, rule_data, set_values)
        log               = {}
        log[:source]      = result_id
        log[:result]      = rule_result
        log[:title]       = rule_data.title
        log[:description] = rule_data.description
        log[:rationale]   = rule_data.rationale
        log[:references]  = rule_data.references.map { |ref| { :href => ref.href, :title => ref.label }}
        log[:fixes]       = populate_fixes rule_data.fixes, set_values
        log[:severity]    = rule_data.severity
        log
      end

      def populate_fixes(fixes, set_values)
        fixes.map do |fix|
          {
            :id => fix.id,
            :system => fix.system,
            :full_text => fix.full_text(set_values)
          }
        end
      end
    end
  end
end
