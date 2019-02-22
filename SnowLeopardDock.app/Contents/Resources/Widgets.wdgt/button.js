/*
Copyright © 2005, Apple Computer, Inc.  All rights reserved.
NOTE:  Use of this source code is subject to the terms of the Software
License Agreement for Mac OS X, which accompanies the code.  Your use
of this source code signifies your agreement to such license terms and
conditions.  Except as expressly granted in the Software License Agreement
for Mac OS X, no other copyright, patent, or other intellectual property
license or right is granted, either expressly or by implication, by Apple.
*/


function createButton (div, title, onaction)
{
	div.style.height = "21px";
	div.style.appleDashboardRegion = 'dashboard-region(control rectangle)';
	var element = document.createElement ('img');
	element.src = 'Images/button_left.png';
	element.style.verticalAlign = "bottom";
	div.appendChild (element);
	
	element = document.createElement('div');
	element.setAttribute ("style", 'font:11px "Helvetica Neue";font-weight:bold;color:rgba(0,0,0,0.7);text-shadow: 0px 1px rgba(255,255,255,0.46);display:inline-block;text-align:center;line-height:20px;background:url(Images/button_center.png) repeat-x top left;vertical-align:bottom;');	
	element.style.height = '20px';
	element.style.paddingBottom = '1px';
	div.appendChild (element);
	element.innerHTML = title;
	
	element = document.createElement ('img');
	element.src = 'Images/button_right.png';
	element.style.verticalAlign = "bottom";
	div.appendChild (element);
	
	div.setAttribute ("onmousedown", "buttonMouseDownHandler(event, this);");
	div.buttonInside = true;
	div.buttonAction = onaction;
	
	// force the images to load.
	var img = new Image;
	img.src = 'Images/button_left_pressed.png';
	var img = new Image;
	img.src = 'Images/button_center_pressed.png';
	var img = new Image;
	img.src = 'Images/button_right_pressed.png';
}

// do not call the following methods directly
var buttonCurrentMouseDownButton = null;
function buttonMouseDownHandler(event, div)
{
	div.childNodes[0].src = 'Images/button_left_pressed.png';
	div.childNodes[1].style.backgroundImage = 'url(Images/button_center_pressed.png)';
	div.childNodes[2].src = 'Images/button_right_pressed.png';
	
	document.addEventListener("mousemove", buttonMouseMoveHandler, true);
	document.addEventListener("mouseup", buttonMouseUpHandler, true);
	div.addEventListener("mouseover", buttonMouseOverHandler, true);
	div.addEventListener("mouseout", buttonMouseOutHandler, true);
	
	div.buttonInside = true;
	buttonCurrentMouseDownButton = div;
	
	event.stopPropagation();
	event.preventDefault();

}

function buttonMouseMoveHandler (event)
{
	event.stopPropagation();
	event.preventDefault();
}

function buttonMouseOverHandler (event)
{
	buttonCurrentMouseDownButton.childNodes[0].src = 'Images/button_left_pressed.png';
	buttonCurrentMouseDownButton.childNodes[1].style.backgroundImage = 'url(Images/button_center_pressed.png)';
	buttonCurrentMouseDownButton.childNodes[2].src = 'Images/button_right_pressed.png';
	
	buttonCurrentMouseDownButton.buttonInside = true;

	event.stopPropagation();
	event.preventDefault();
}

function buttonMouseOutHandler (event)
{
	buttonCurrentMouseDownButton.childNodes[0].src = 'Images/button_left.png';
	buttonCurrentMouseDownButton.childNodes[1].style.backgroundImage = 'url(Images/button_center.png)';
	buttonCurrentMouseDownButton.childNodes[2].src = 'Images/button_right.png';

	buttonCurrentMouseDownButton.buttonInside = false;
	
	event.stopPropagation();
	event.preventDefault();
}

function buttonMouseUpHandler (event)
{
	buttonCurrentMouseDownButton.childNodes[0].src = 'Images/button_left.png';
	buttonCurrentMouseDownButton.childNodes[1].style.backgroundImage = 'url(Images/button_center.png)';
	buttonCurrentMouseDownButton.childNodes[2].src = 'Images/button_right.png';

	// callback to the client
	document.removeEventListener("mousemove", buttonMouseMoveHandler, true);
	document.removeEventListener("mouseup", buttonMouseUpHandler, true);	
	buttonCurrentMouseDownButton.removeEventListener("mouseover", buttonMouseOverHandler, true);
	buttonCurrentMouseDownButton.removeEventListener("mouseout", buttonMouseOutHandler, true);
		
	event.stopPropagation();
	event.preventDefault();
		
	if (buttonCurrentMouseDownButton.buttonAction && buttonCurrentMouseDownButton.buttonInside)
	{
		buttonCurrentMouseDownButton.buttonAction();
	}
	
	buttonCurrentMouseDownButton = null;
}
