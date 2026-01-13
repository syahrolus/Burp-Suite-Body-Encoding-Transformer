from burp import IBurpExtender, ITab
from javax.swing import (
    JPanel, JTextArea, JButton, JComboBox, JScrollPane, JLabel
)
from java.awt import BorderLayout, GridLayout
import json
import uuid
import urllib
import re
from javax.xml.parsers import DocumentBuilderFactory
from org.xml.sax import InputSource
from java.io import StringReader


class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Body Encoding Transformer")

        self.panel = JPanel(BorderLayout())

        # Top menu
        options = JPanel(GridLayout(1, 3))
        options.add(JLabel("Transform To:"))

        self.transformBox = JComboBox([
            "JSON",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "XML"
        ])

        options.add(self.transformBox)

        self.convertBtn = JButton("Convert", actionPerformed=self.convert)
        options.add(self.convertBtn)

        self.panel.add(options, BorderLayout.NORTH)

        # Text areas
        self.inputArea = JTextArea(20, 80)
        self.outputArea = JTextArea(20, 80)

        self.panel.add(JScrollPane(self.inputArea), BorderLayout.WEST)
        self.panel.add(JScrollPane(self.outputArea), BorderLayout.CENTER)

        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Body Encoder"

    def getUiComponent(self):
        return self.panel

    # ---------------- CORE ---------------- #

    def convert(self, event):
        try:
            raw = self.inputArea.getText()
            headers, body = self.split_request(raw)

            data = self.parse_body(headers, body)
            mode = self.transformBox.getSelectedItem()

            if mode == "JSON":
                new_body = json.dumps(data)
                headers = self.set_content_type(headers, "application/json")

            elif mode == "application/x-www-form-urlencoded":
                new_body = self.to_urlencoded(data)
                headers = self.set_content_type(
                    headers, "application/x-www-form-urlencoded"
                )

            elif mode == "multipart/form-data":
                boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
                new_body = self.to_multipart(data, boundary)
                headers = self.set_content_type(
                    headers, "multipart/form-data; boundary=" + boundary
                )

            elif mode == "XML":
                new_body = self.to_xml(data)
                headers = self.set_content_type(headers, "application/xml")

            headers = self.fix_content_length(headers, new_body)
            self.outputArea.setText(headers + "\r\n\r\n" + new_body)

        except Exception as e:
            self.outputArea.setText("Error: " + str(e))


    # ---------------- HELPERS ---------------- #

    def split_request(self, request):
        if "\r\n\r\n" in request:
            return request.split("\r\n\r\n", 1)
        elif "\n\n" in request:
            return request.split("\n\n", 1)
        else:
            raise Exception("Invalid HTTP request")

    def parse_body(self, headers, body):
        body = body.strip()

        for i in headers.split("\r\n")[0].split("\n"):
            if i.lower().startswith("content-type"):
                content_type = i.lower()
                break

        if "application/json" in content_type:
            return json.loads(body)
        elif "application/x-www-form-urlencoded" in content_type:
            # Try application/x-www-form-urlencoded
            data = {}
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    data[urllib.unquote(k)] = urllib.unquote(v)
            return data
        elif "multipart/form-data" in content_type:
            pattern = re.compile(r'Content-Disposition:\s*form-data;\s*name="([^"]+)"\s*\r?\n\r?\n(.*?)\r?\n(?=--)',re.S)
            data = {}
            for key, value in pattern.findall(body):
                data[key] = value.strip()
            return data
        elif "application/xml" in content_type:
            factory = DocumentBuilderFactory.newInstance()
            factory.setNamespaceAware(False)
            factory.setValidating(False)

            builder = factory.newDocumentBuilder()
            doc = builder.parse(InputSource(StringReader(body)))

            root = doc.getDocumentElement()
            nodes = root.getChildNodes()

            data = {}

            for i in range(nodes.getLength()):
                node = nodes.item(i)
                if node.getNodeType() == node.ELEMENT_NODE:
                    data[node.getNodeName()] = node.getTextContent().strip()

            return data

    def set_content_type(self, headers, value):
        lines = headers.split("\r\n")[0].split("\n")
        out = []
        found = False

        for l in lines:
            if l.lower().startswith("content-type"):
                out.append("Content-Type: " + value)
                found = True
            else:
                out.append(l)

        if not found:
            out.append("Content-Type: " + value)

        return "\r\n".join(out)

    def fix_content_length(self, headers, body):
        lines = headers.split("\r\n")
        out = []

        for l in lines:
            if not l.lower().startswith("content-length"):
                out.append(l)

        out.append("Content-Length: " + str(len(body)))
        return "\r\n".join(out)

    def to_multipart(self, data, boundary):
        body = ""
        for k, v in data.items():
            body += "--" + boundary + "\r\n"
            body += 'Content-Disposition: form-data; name="{}"\r\n\r\n'.format(k)
            body += str(v) + "\r\n"
        body += "--" + boundary + "--"
        return body

    def to_xml(self, data):
        xml = '<?xml version="1.0" encoding="UTF-8"?>\n<request>\n'
        for k, v in data.items():
            xml += "  <{0}>{1}</{0}>\n".format(k, v)
        xml += "</request>"
        return xml

    def to_urlencoded(self, data):
        pairs = []
        for k, v in data.items():
            pairs.append(
                "{}={}".format(
                    urllib.quote(str(k)),
                    urllib.quote(str(v))
                )
            )
        return "&".join(pairs)
