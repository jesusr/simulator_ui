class TableInterfaz
  constructor: (url,flavours)->
    if(typeof(url) is "string" && typeof(flavours) is "string")
      $.getJSON url, {}, (data)-> 
        switch (data.node_type)
          when 'CVEs'
            new CVETable(data)
          when 'Software'
            new SWTable(data)
          when 'Instances'
            new InsTable(data,flavours)
    else if(typeof(url) is "object")
      switch (url.node_type)
        when 'CVEs'
          new CVETable(url)
        when 'software'
          new SWTable(url)
        when 'Instances'
          new InsTable(url,flavours)
class Table
  setPriority: (cvss)-> 
    if cvss>4 then 'red' else if cvss == 0 then 'green' else 'yellow'
  parseDate: (d)->
    dd = d.slice(0,10).split '-'
    dd[2]+"/"+dd[1]+"/"+dd[0]
class InsTable extends Table
  constructor: (data,flav)->
    div = InsTable.paint(data,flav)
    $('#instances').append(div)
  @paint: (data,flav)->
    toret='<table class="instances row"><thead><tr><th></th><th></th><th></th></tr></thead><tbody>'
    $.each data.instances,->  
      toret+=InsTable.addItem(this,flav)
    toret+='</tbody></table>'
  @addItem: (item,flav)->
    art = "<tr><td>"+item.num+"</td><td>"+item.flavour+"</td>"
    $.each flav.flavours,->
      if this.name is item.flavour
        art+="<td>"+this.memory+"</td><td>"+this.disk+"</td><td>"+this.vcpu+"</td></tr>"
    art
class CVETable extends Table
  constructor: (data)->
    div = "<h3>"+data.node_type+": "+data.name+"</h3>"    
    div+= CVETable.paint(data)
    $('#breadcrumb').append('<li>CVE</li>')
    $('.table').empty().append div
    $('#cvetable article').click (event)->
      $(this).toggleClass("viewfull",400)
    return       
  @paint: (data)->
    toret='<div id="cvetable"><article id="leyend"><p class="risk"><span>Riesgo</span></p><p class="known"><span>Conocido desde </span></p><p class="updated"><span>Última actualizaci&oacute;n </span></p><p class="cod"><span>Código</span></p></article>'
    $.each data.cve,->  
      toret+=CVETable.addItem(this)
    toret+='</div>'
  @addItem: (item)->
    art = "<article data-cvss='"+item.cvss
    art +="' id='"+item.cve
    art +="' class='cve"
    art +="'><p class='risk "+Table::setPriority(item.cvss)+"'>"+item.cvss
    art +="</p><p class='known'>"+CVETable::parseDate(item.published)
    art +="</p><p class='updated'>"+CVETable::parseDate(item.modified)
    art +="</p><p class='cod'>"+item.cve
    art +="</p><div class='cve-more'><span>Summary: </span>"+item.summary
    art +="</div></article>"
    art
class SWTable extends Table 
  constructor:(data)->
    div = "<h3>"+data.node_type+" de "+data.id
    if data.for is "Machine"
      div+= " (M&aacute;quina)</h3>"
    else div+= "</h3>" 
    div+= SWTable.paint(data)
    $('#breadcrumb').append('<li><a>Software</a></li>')
    $('.table').empty().append div
    $('button.details').click (event)->
      $(this).parent().toggleClass("viewfull",400)
      return
    $('button.viewFullList').click (event)->
      TableInterfaz("assets/force.json")
      return
  @paint:(data)->
    toret='<div id="swtable"><article id="leyend"><p class="cve_critical"><span>Critical</span></p><p class="cve_warning"><span>Warning</span></p><p class="sw_name"><span>Software</span></p><p class="version"><span>Versi&oacute;n</span></p></article>'
    $.each data.sw,->
      toret+=SWTable.addItem(this)
    toret+='</div>'
  @addItem:(item)->
    art ='<article id="'+item.publisher+'-'+item.software+'-'+item.version+'" class="software '+item.publisher+'">'
    art+='<p class="cve_critical">'+item.cve_critical+'</p>'
    art+='<p class="cve_warning">'+item.cve_warning+'</p>'
    art+='<p class="sw_name">'+item.publisher+' '+item.software+'</p>'
    art+='<p class="version">'+item.version+'</p>'
    art+='<button class="details">Detalles</button><div>'
    $.each item.cve,->
      art+='<article><p><span class="risk '+SWTable::setPriority(this.cvss)+'">'+this.cvss+'</span><p><span class="cve_id">'+this.cve+'</span></p><p><span class="known">'+CVETable::parseDate(this.published)+'</span></p></article>'
    art+='</div>'
    art+='<button class="viewFullList">Ver m&aacute;s</button>'
    art+='</article>'
$ ->
  instances = {
    "node_type":"Instances",
    "instances":[
      {
        "flavour":"tiny",
        "num":"3"
      },
      {
        "flavour":"xlarge",
        "num": "8"
      }
    ]
  }
  flavours = {
    "node_type":"flavours",
    "flavours":[
      {
        "id":"1",
        "name":"tiny",
        "memory": "512MB",
        "disk": "0",
        "vcpu": "1"
      },
      {
        "id":"5",
        "name":"xlarge",
        "memory":"2GB",
        "disk":"5TB",
        "vcpu":"12"
      },
    ]
  }
  TableInterfaz(instances,flavours)