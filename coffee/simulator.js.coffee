$(document).ready ->
	$('.notesite').hover(
		-> 
			$(this).animate {'font-size': '1200%'},200
			return
		-> 
			$(this).animate {'font-size': '1140%'},200
			return
	).on 'click', (e) ->
	  if $('div#resume').hasClass("open")
      $('div#resume').removeClass("open",400)
    else
      $('div#resume').addClass("open",400)
		return
	$('#resume .hide').on('click', (e) ->
		$('#resume').animate {'height': '0'},300
		return
	)	
	return
