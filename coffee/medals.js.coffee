class Medals
	constructor: (list) ->
		if list.length is 3 then list.forEach (el) => new Medal(el)
class Medal
	constructor: (el) ->
		li = '<span class="int">'+el.int+'</span>'
		li+= '<span class="dec">'+el.dec+'</span>' if el.dec?
		li+= '<span class="leyend">'+el.leyend+'</span>'
		switch el.noteType
			when "instances"
				$('.instances .notesite .percent').append(li)
			when "disk"
				$('.disk .notesite .percent').append(li)
			when "memory"
				$('.memory .notesite .percent').append(li)
$ ->
	json = {
		"nodeType":"notes",
		"notes":[
			{
				"noteType":"instances",
				"int":"12",
				"dec":null,
				"leyend":"Instancias"
			},
			{
				"noteType":"disk",
				"int":"800",
				"dec":null,
				"leyend":"GB de Disco"
			},
			{
				"noteType":"memory",
				"int":"180",
				"dec":null,
				"leyend":"GB de Memoria"
			}
		]
	}
	toPrint = new Medals(json.notes)dec":null,
				"leyend":"GB de Memoria"
			}
		]
	}
	toPrint = new Medals(json.notes)