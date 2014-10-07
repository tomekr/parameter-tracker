require 'java'
require 'pry'
java_import 'burp.IBurpExtender'
java_import 'burp.ITab'
java_import 'burp.IHttpListener'
java_import 'burp.IMessageEditorController'

class BurpExtender
  include IBurpExtender, ITab, IHttpListener, IMessageEditorController

  #
  # implement IBurpExtender
  #

  def	registerExtenderCallbacks(callbacks)

    # keep a reference to our callbacks object
    @callbacks = callbacks

    # obtain an extension helpers object
    @helpers = callbacks.getHelpers()

    # set our extension name
    callbacks.setExtensionName("Paramater Tracker")

    # create the log
    @log = java.util.ArrayList.new()
    @mutex = Mutex.new()

    # main split pane
    @mainpane = javax.swing.JSplitPane.new(1)
    @rightpane = javax.swing.JSplitPane.new(0)

    # Setup left pane
    @tableModel = LogTableModel.new(self, @log)
    logTable = Table.new(self, @tableModel)
    scrollPane = javax.swing.JScrollPane.new(logTable)
    @mainpane.setTopComponent(scrollPane)

    # Setup Right Pane

    # table of log entries
    @tableModel = LogTableModel.new(self, @log)
    logTable = Table.new(self, @tableModel)
    scrollPane = javax.swing.JScrollPane.new(logTable)
    @rightpane.setLeftComponent(scrollPane)

    # tabs with request/response viewers
    tabs = javax.swing.JTabbedPane.new()
    @requestViewer = callbacks.createMessageEditor(self, false)
    @responseViewer = callbacks.createMessageEditor(self, false)
    tabs.addTab("Request", @requestViewer.getComponent())
    tabs.addTab("Response", @responseViewer.getComponent())
    @rightpane.setRightComponent(tabs)


    @mainpane.setBottomComponent(@rightpane)

    # customize our UI components
    callbacks.customizeUiComponent(@mainpane)
    callbacks.customizeUiComponent(logTable)
    callbacks.customizeUiComponent(scrollPane)
    callbacks.customizeUiComponent(tabs)

    # add the custom tab to Burp's UI
    callbacks.addSuiteTab(self)

    # register ourselves as an HTTP listener
    callbacks.registerHttpListener(self)

  end

  #
  # implement ITab
  #

  def getTabCaption()
    return "Parameters"
  end

  def getUiComponent()
    return @mainpane
  end

  #
  # implement IHttpListener
  #

  def processHttpMessage(toolFlag, messageIsRequest, message_info)

    # only process requests
    if (!messageIsRequest)
      # create a new log entry with the message details
      @mutex.synchronize do
        @helpers.analyze_request(message_info).parameters.each do |parameter|
          row = @log.size()
          @log.add(LogEntry.new(parameter.name, @callbacks.saveBuffersToTempFiles(message_info), @helpers.analyzeRequest(message_info).getUrl()))
          @tableModel.fireTableRowsInserted(row, row)
        end
	    end
    end
  end

  #
  # implement IMessageEditorController
  # this allows our request/response viewers to obtain details about the messages being displayed
  #

  def getHttpService()
    return @currentlyDisplayedItem.getHttpService()
  end

  def getRequest()
    return @currentlyDisplayedItem.getRequest()
  end

  def getResponse()
    return @currentlyDisplayedItem.getResponse()
  end

	#
  # getter / setters
 	#

  def callbacks
    @callbacks
  end

  def log
    @log
  end

  def requestViewer
    @requestViewer
  end

  def responseViewer
    @responseViewer
  end

  def currentlyDisplayedItem=(currentlyDisplayedItem)
    @currentlyDisplayedItem = currentlyDisplayedItem
  end

end


#
# class extending DefaultTableModel
#

class LogTableModel < javax.swing.table.DefaultTableModel

  def initialize(extender, log)
    super 0, 0
    @extender = extender
    @log = log
  end

  def getRowCount()
    begin
      return @log.size()
    rescue
      return 0
    end
  end

  def getColumnCount()
    return 2
  end

  def getColumnName(columnIndex)
    if (columnIndex == 0)
      return "Parameter"
    end
    if (columnIndex == 1)
      return "URL"
    end
    return ""
  end

  def getValueAt(rowIndex, columnIndex)
    logEntry = @log.get(rowIndex)
    if (columnIndex == 0)
      return logEntry.pname
    end
    if (columnIndex == 1)
      return logEntry.url.toString()
    end
    return ""
  end

end


#
# extend JTable to handle cell selection
#

class Table < javax.swing.JTable

  def initialize(extender, tableModel)
    super tableModel
    @extender = extender
  end

  def changeSelection(row, col, toggle, extend)

    # show the log entry for the selected row
    logEntry = @extender.log.get(row)
    @extender.requestViewer.setMessage(logEntry.requestResponse.getRequest(), true)
    @extender.responseViewer.setMessage(logEntry.requestResponse.getResponse(), false)
    @extender.currentlyDisplayedItem = logEntry.requestResponse

    super(row, col, toggle, extend)
  end

end


#
# class to hold details of each log entry
#

class LogEntry

  def initialize(pname, requestResponse, url)
    @pname = pname
    @requestResponse = requestResponse
    @url = url
  end

	#
	# getter / setters
	#

  def pname
    @pname
  end

  def requestResponse
    @requestResponse
  end

  def url
    @url
  end

end
