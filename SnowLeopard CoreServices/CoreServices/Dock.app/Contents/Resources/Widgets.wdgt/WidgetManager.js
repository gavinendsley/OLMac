/*
Copyright © 2005, Apple Computer, Inc.  All rights reserved.
NOTE:  Use of this source code is subject to the terms of the Software
License Agreement for Mac OS X, which accompanies the code.  Your use
of this source code signifies your agreement to such license terms and
conditions.  Except as expressly granted in the Software License Agreement
for Mac OS X, no other copyright, patent, or other intellectual property
license or right is granted, either expressly or by implication, by Apple.
*/

var scrollArea = null;
var scroller = null;
var min_middle_height = 210;
var curr_middle_height = 210;
var dialog = null;

var sort_options = [{name:'Sort by Name', sortProc:sortByNameProc},
					{name:'Sort by Date', sortProc:sortByDateProc}];
					
var sort_preference_index = 0; // can be name - 0,date - 1,enabled - 2
var need_to_sort_next_time_db_is_shown = false;

var allTheWidgets = new Array;

allTheWidgets = [{order:1, id:'1', enabled:true, icon:'file:///Library/Widgets/Address%20Book.wdgt/Icon.png', label:"Address Book", can_delete:true, date:1},
				 {order:2, id:'2', enabled:false, icon:'file:///Library/Widgets/Calculator.wdgt/Icon.png', label:"Calculator", can_delete:false, date: 2},
				 {order:3, id:'3', enabled:true, icon:'none', label:"Overflow text case, it should overflow", can_delete:true, date:3},
				 {order:4, id:'4', enabled:true, icon:'none', label:"One more is four", can_delete:true, data:4}];
				 
var enabled_count = 3; // must match test data

function getLocalizedString (key)
{
	try {
		var ret = localizedStrings[key];
		if (ret === undefined)
			ret = key;
		return ret;
	} catch (ex) {}

	return key;
}

function createKey (key)
{
	return widget.identifier + "-" + key
}


if (window.widgetManager)
{
	widgetManager.ondeletewidget = deleteWidget;
	widgetManager.onwidgetschanged = widgetsChanged;
}

if (window.widget)
{
	widget.onremove = remove;
	widget.onhide = hide;
}

function load ()
{
	var needToResize = false;
	document.getElementById('disable-help').innerText = getLocalizedString ('Uncheck Widgets to disable them.');
	
	populateSortSelect();
	
	if (window.widget)
	{
		var pref = widget.preferenceForKey (createKey('mid-height'));
		if (pref != null)
		{
			curr_middle_height = parseInt (pref, 10);
			if (curr_middle_height < min_middle_height)
				curr_middle_height = min_middle_height;
				
			if (curr_middle_height != 210) // starting height
			{
				needToResize = true;
			}
		}
	}
	
	document.getElementById('mid').style.height = curr_middle_height + "px";
	document.getElementById('bottom').style.top = curr_middle_height + 76 + "px";
	
	createButton (document.getElementById('more-widget-button'), getLocalizedString ('More Widgets…'), more_widgets);
	
	sort_preference_index = getSortPreferenceIndex();
	document.getElementById('sort-popup-text').innerText = getLocalizedString (sort_options[sort_preference_index].name);
	document.getElementById('sort-select').selectedIndex = sort_preference_index;
	
	if (window.widgetManager)
	{
		getAllWidgets();
	}
	buildTable();
	
	createScroller();
	
	// preload the images
	var image = new Image;
	image.src = 'Images/widget-small.png';
	image = new Image;
	image.src = 'Images/widget-58.png';
	
	if (needToResize)
		window.resizeTo (298, curr_middle_height + 76 + 45); // 76 is top, 45 bottom
}

function remove ()
{
	widget.setPreferenceForKey (null, createKey('mid-height'));
}

function hide ()
{
	if (need_to_sort_next_time_db_is_shown && sort_preference_index == 2)
	{
		allTheWidgets.sort (sort_options[sort_preference_index].sortProc);
		buildTable();
	}
	
	need_to_sort_next_time_db_is_shown = false;

}

function getSortPreferenceIndex ()
{
	var index= 0;
	
	if (window.widget)
	{
		var pref = widget.preferenceForKey('sort');
	
		if (pref != null)
		{
			switch (pref)
			{
				case 'name': index = 0; break;
				case 'date': index = 1; break;
			}
		}
	}

	return index;
}

function writeSortPreference() {
	if (window.widget)
	{
		var value = 'name';
		
		switch (sort_preference_index)
		{
			case 0: value='name'; break;
			case 1: value='date'; break;
		}
		
		widget.setPreferenceForKey(value, 'sort');
	}
}


function createScroller ()
{
	scroller = new AppleVerticalScrollbar(document.getElementById('scroller'));
	scroller.setTrackStart("Images/top_scroll_track.png", 17);
	scroller.setTrackMiddle("Images/mid_scroll_track.png");
	scroller.setTrackEnd("Images/bottom_scroll_track.png", 17);
	scrollArea = new AppleScrollArea(document.getElementById('content-frame'), scroller);
	scroller.setAutohide(false);
}


function refreshScroller ()
{
	scrollArea.refresh();
	scroller.refresh();
}


function getAllWidgets ()
{
	var array = widgetManager.getWidgets();
	
	if (array)
	{
		var c = array.length;
		
		allTheWidgets.length = 0;
		enabled_count = 0;
		
		for (var i = 0; i < c; ++i)
		{
			var obj = array[i];
			allTheWidgets[i] = {order: i, 
								enabled: obj.enabled,
								label: obj.label,
								id: obj.bundleId,
								icon: obj.iconPath,
								can_delete: obj.canDelete,
								date: obj.installedDate};
								
			if (obj.enabled)
				enabled_count++;
		}
		
		if (sort_preference_index != 0)
		{
			allTheWidgets.sort (sort_options[sort_preference_index].sortProc);
		}
	}
}
function populateSortSelect ()
{
	var select = document.getElementById('sort-select');
	
	var c = sort_options.length;
	for (var i=0; i < c; ++i)
	{
		var option = document.createElement('option');
		option.innerText = getLocalizedString(sort_options[i].name);
		select.appendChild(option);
	}
	
}

//
// Handling the table
//

function buildTable ()
{
	var table = document.getElementById('content-table');
	
	while (table.hasChildNodes())
	{
		table.removeChild(table.firstChild);
	}
		
	var enabled_text = getLocalizedString('enabled');
	var disabled_text = getLocalizedString('disabled');
	
	var c = allTheWidgets.length;
	for (var i  = 0; i < c; ++i)
	{
		var obj = allTheWidgets[i];
		
		var row = document.createElement('div');
		row.widgetId = obj.id;
		
		// the check column
		var img = document.createElement('img');
		if (obj.enabled)
		{
			img.src = 'Images/checked.png';
			img.alt = enabled_text;
			row.setAttribute('class', 'content-row');
		}
		else
		{
			img.src = 'Images/unchecked.png';
			img.alt = disabled_text;
			row.setAttribute('class', 'content-row text-disabled');
		}
		img.setAttribute('onmousedown', 'enable_mouse_down_handler(event, this);');
		img.setAttribute('class', 'check-image');
		row.appendChild (img);
		
		// the icon column
		img = document.createElement('img');
		img.src = obj.icon;
		img.setAttribute('class', 'icon-image');
		img.setAttribute('onerror', 'iconFailedToLoad(event, this);');
		img.setAttribute('ondblclick', 'handleDoubleClick (event, this);');
		img.height='24';
		img.width='24';
		row.appendChild(img);
				
		// the title column
		var div = document.createElement('div')
		div.setAttribute ('class', 'label-div');
		div.appendChild (document.createTextNode(obj.label));
		div.setAttribute('ondblclick', 'handleDoubleClick (event, this);');
		row.appendChild (div);
		
		// the delete column
		if (obj.can_delete)
		{
			img = document.createElement('img');
			img.src = 'Images/delete.png';
			img.setAttribute('class', 'delete-image');
			img.setAttribute('onmousedown', 'delete_mouse_down_handler(event, this);');
			img.setAttribute('onmouseover', 'delete_mouse_over_handler(event, this);');
			img.setAttribute('onmouseout', 'delete_mouse_out_handler(event, this)');
			img.alt = "delete";
			row.appendChild (img);
		}
		
		table.appendChild(row);
	}
}

function iconFailedToLoad(event, img)
{
	if (img.src != 'Images/widget-small.png')
		img.src = 'Images/widget-small.png';
}

function iconFailedToLoadDialog(event, img)
{
	if (img.src != 'Images/widget-58.png')
		img.src = 'Images/widget-58.png';
}

function more_widgets ()
{
	if (window.widget)
	{
		widget.openURL(getLocalizedString('http://www.apple.com/macosx/dashboard/'));
	}
}


function enableSortPopup (enabled)
{
	if (enabled)
	{
		document.getElementById('sort-select').disabled = '';
		document.getElementById('sort-popup-text').style.opacity = 1;
		document.getElementById('sort-popup').style.opacity = 1;
	}
	else
	{
		document.getElementById('sort-select').disabled = 'disabled';
		document.getElementById('sort-popup-text').style.opacity = 0.5;
		document.getElementById('sort-popup').style.opacity = 0.5;
	}

}

function indexOfWidgetWithBundleId(bundle_id)
{
	var c = allTheWidgets.length;
	for (var i=0; i < c; ++i)
	{
		if (allTheWidgets[i].id == bundle_id)
		{
			return i;
		}
	}
	
	return -1;
}

//
// widgetManager handlers
// 
function deleteWidget (bundle_id, success)
{
	if (dialog != null)
	{
		var index = indexOfWidgetWithBundleId (bundle_id);
		
		// it is the widget for this dialog
		if (dialog.widgetIndex == index)
		{
			if (success)
			{
				var table = document.getElementById('content-table');
				var row = table.childNodes[index];
				row.parentNode.removeChild (row);
				refreshScroller();
				allTheWidgets.splice(index, 1);
			}
			
			setupDialogAnimation (175, 1, 0);
		}
	}
}

function widgetsChanged ()
{
	// close any dialogs if we get a widget changed message
	if (dialog != null)
	{
		setupDialogAnimation (175, 1, 0);
	}
	getAllWidgets ();
	buildTable();
	refreshScroller();
}

//
//
// sort methods
//

function sortByNameProc (a, b)
{
	return a.order - b.order;
}

function sortByDateProc (a, b)
{
	if (b.date == a.date)
		return a.order - b.order;
	else
		return b.date - a.date;
}

function sortByEnabledProc (a, b)
{
	if (a.enabled == b.enabled)
		return a.order - b.order;
	else if (a.enabled)
		return -1;
	else
		return 1;
}

//
// event handlers
//

var trackingElement = null;
function close_mouse_down_handler (event, img)
{
	document.addEventListener("mousemove", empty_mouse_move_handler, true);
	document.addEventListener("mouseup", close_mouse_up_handler, true);

	img.addEventListener("mouseover", close_mouse_over_handler, true);
	img.addEventListener("mouseout", close_mouse_out_handler, true);
	img.src = 'Images/close_press.png';

	trackingElement = img;
	trackingElement.mouseInElement = true;
	event.stopPropagation();
	event.preventDefault();
}

function empty_mouse_move_handler (event)
{
	event.stopPropagation();
	event.preventDefault();
}

function close_mouse_up_handler (event)
{
	document.removeEventListener("mousemove", empty_mouse_move_handler, true);
	document.removeEventListener("mouseup", close_mouse_up_handler, true);
	trackingElement.removeEventListener("mouseover", close_mouse_over_handler, true);
	trackingElement.removeEventListener("mouseout", close_mouse_out_handler, true);
	
	var doit = trackingElement.mouseInElement;
	trackingElement.mouseInElement = false;
	trackingElement.src = 'Images/close_normal.png';
	trackingElement = null;
	
	if (doit)
	{
		if (window.widgetManager)
		{
			widgetManager.close (event.shiftKey);
		}
	}

	event.stopPropagation();
	event.preventDefault();
}

function close_mouse_over_handler (event)
{
	if (!trackingElement.mouseInElement)
	{
		trackingElement.mouseInElement = true;
		trackingElement.src = 'Images/close_press.png';
	}

	event.stopPropagation();
	event.preventDefault();

}

function close_mouse_out_handler (event)
{
	if (trackingElement.mouseInElement)
	{
		trackingElement.mouseInElement = false;
		trackingElement.src = 'Images/close_normal.png';
	}

	event.stopPropagation();
	event.preventDefault();
}

function sort_popup_changed (event, select)
{
	sort_preference_index = select.selectedIndex;
	document.getElementById('sort-popup-text').innerText = getLocalizedString(sort_options[sort_preference_index].name);
	
	allTheWidgets.sort (sort_options[sort_preference_index].sortProc);
	buildTable();
	need_to_sort_next_time_db_is_shown = false;
	
	writeSortPreference();

	event.stopPropagation();
	event.preventDefault();
}

var resize_start_pos = null;
var resize_height = null;
function resize_mouse_down_handler (event, img)
{
	document.addEventListener("mousemove", resize_mouse_move_handler, true);
	document.addEventListener("mouseup", resize_mouse_up_handler, true);

	trackingElement = img;

	resize_last_y = event.y;
	resize_size = curr_middle_height;
	
	event.stopPropagation();
	event.preventDefault();
}

function resize_mouse_move_handler (event)
{
	var deltay = event.y - resize_last_y;
	resize_last_y = event.y;
	
	var need_to_resize_to_min = false;
	if (resize_size > min_middle_height)
		need_to_resize_to_min = true;
		
	resize_size += deltay;
	
	if (resize_size >= min_middle_height || need_to_resize_to_min)
	{
		var mid_size = resize_size;
		if (resize_size < min_middle_height)
			mid_size = min_middle_height;
		
		document.getElementById('mid').style.height = mid_size + 'px';
		document.getElementById('bottom').style.top = 76 + mid_size + 'px';
		curr_middle_height = mid_size;
		refreshScroller();		
		if (dialog != null)
			dialog.refresh();
		
		if (window.widget)
		{
			window.resizeTo (298, mid_size + 76 + 45); // 76 is top, 45 bottom
		}
	}
	
	event.stopPropagation();
	event.preventDefault();
}

function resize_mouse_up_handler (event)
{
	document.removeEventListener("mousemove", resize_mouse_move_handler, true);
	document.removeEventListener("mouseup", resize_mouse_up_handler, true);
	
	trackingElement = null;
	
	if (window.widget)
	{
		widget.setPreferenceForKey (curr_middle_height.toString(), createKey('mid-height'));
	}

	
	event.stopPropagation();
	event.preventDefault();
}

function enable_mouse_down_handler (event, img)
{
	document.addEventListener("mousemove", empty_mouse_move_handler, true);
	document.addEventListener("mouseup", enable_mouse_up_handler, true);

	img.addEventListener("mouseover", enable_mouse_over_handler, true);
	img.addEventListener("mouseout", enable_mouse_out_handler, true);
	
	img.widgetIndex = indexOfWidgetWithBundleId(img.parentNode.widgetId);
	img.src = allTheWidgets[img.widgetIndex].enabled ? 'Images/checked_pressed.png' : img.src = 'Images/unchecked_pressed.png';

	trackingElement = img;
	trackingElement.mouseInElement = true;

	event.stopPropagation();
	event.preventDefault();
}

function enable_mouse_up_handler (event)
{

	document.removeEventListener("mousemove", empty_mouse_move_handler, true);
	document.removeEventListener("mouseup", enable_mouse_up_handler, true);
	trackingElement.removeEventListener("mouseover", enable_mouse_over_handler, true);
	trackingElement.removeEventListener("mouseout", enable_mouse_out_handler, true);
	
	var doit = trackingElement.mouseInElement;
	var index = trackingElement.widgetIndex;
	trackingElement.mouseInElement = false;
	
	var widget = allTheWidgets[index];
	if (doit)
	{
		widget.enabled = !widget.enabled;
		
		enabled_count += widget.enabled ? 1 : -1;
		if (enabled_count > 0) // dont allow disabling the last_widget
		{
			var row = trackingElement.parentNode;
			if (row != null)
			{
				if (widget.enabled)
					row.setAttribute ('class', 'content-row');
				else
					row.setAttribute ('class', 'content-row text-disabled');
			}
			
			if (window.widgetManager)
			{
				widgetManager.enableWidget(widget.id, widget.enabled);
			}
			
			if (sort_preference_index == 2) // are we sorting by the enabled flag
			{
				need_to_sort_next_time_db_is_shown = true;
			
			}
		}
		else
		{
			widget.enabled = !widget.enabled; // reverse our change, dont allow disabling of last widget
			enabled_count = 1;
		}
	}

	if (widget.enabled)
	{
		trackingElement.src = 'Images/checked.png';
		trackingElement.alt = getLocalizedString('enabled');
	}
	else
	{
		trackingElement.src = 'Images/unchecked.png';
		trackingElement.alt = getLocalizedString('disabled');
	}
	
	trackingElement = null;
	
	event.stopPropagation();
	event.preventDefault();
}

function enable_mouse_over_handler (event)
{
	if (!trackingElement.mouseInElement)
	{
		trackingElement.mouseInElement = true;

		var widget = allTheWidgets[trackingElement.widgetIndex];
		
		trackingElement.src = widget.enabled ? 'Images/checked_pressed.png' : 'Images/unchecked_pressed.png';
	}

	event.stopPropagation();
	event.preventDefault();

}

function enable_mouse_out_handler (event)
{
	if (trackingElement.mouseInElement)
	{
		trackingElement.mouseInElement = false;
		var widget = allTheWidgets[trackingElement.widgetIndex];
		
		trackingElement.src = widget.enabled ? 'Images/checked.png' : 'Images/unchecked.png';
	}

	event.stopPropagation();
	event.preventDefault();
}


function delete_mouse_down_handler (event, img)
{
	document.addEventListener("mousemove", empty_mouse_move_handler, true);
	document.addEventListener("mouseup", delete_mouse_up_handler, true);

	img.addEventListener("mouseover", delete_mouse_over2_handler, true);
	img.addEventListener("mouseout", delete_mouse_out2_handler, true);
	
	img.widgetIndex = indexOfWidgetWithBundleId(img.parentNode.widgetId);
	img.src = 'Images/delete_press.png';

	trackingElement = img;
	trackingElement.mouseInElement = true;

	event.stopPropagation();
	event.preventDefault();
}

function delete_mouse_up_handler (event)
{
	document.removeEventListener("mousemove", empty_mouse_move_handler, true);
	document.removeEventListener("mouseup", delete_mouse_up_handler, true);
	trackingElement.removeEventListener("mouseover", delete_mouse_over2_handler, true);
	trackingElement.removeEventListener("mouseout", delete_mouse_out2_handler, true);
	
	trackingElement.src = 'Images/delete.png';
	
	if (trackingElement.mouseInElement && allTheWidgets.length > 1)
	{
		var widget = allTheWidgets[trackingElement.widgetIndex];
		dialog = new Dialog (widget.label,getLocalizedString('Move this widget to the Trash?'), widget.icon);		
		setupDialogAnimation (250, 0, 1);
		dialog.widgetIndex = trackingElement.widgetIndex;
		
		//turn off the popup
		enableSortPopup (false);
	}
	trackingElement.mouseInElement = false;
	trackingElement = null;

	event.stopPropagation();
	event.preventDefault();
}

function delete_mouse_over_handler (event, img)
{
	img.src = 'Images/delete_roll.png';
	event.stopPropagation();
	event.preventDefault();

}

function delete_mouse_out_handler (event, img)
{
	img.src = 'Images/delete.png';
	event.stopPropagation();
	event.preventDefault();

}


function delete_mouse_over2_handler (event)
{
	if (!trackingElement.mouseInElement)
	{
		trackingElement.mouseInElement = true;
		trackingElement.src = 'Images/delete_press.png';
	}

	event.stopPropagation();
	event.preventDefault();

}


function delete_mouse_out2_handler (event)
{
	if (trackingElement.mouseInElement)
	{
		trackingElement.mouseInElement = false;
		trackingElement.src = 'Images/delete.png';
	}

	event.stopPropagation();
	event.preventDefault();
}

function handleDoubleClick (event, element)
{
	if (window.widgetManager)
	{
		var widget = allTheWidgets[indexOfWidgetWithBundleId(element.parentNode.widgetId)];
		
		if (widget.enabled)
		{
			widgetManager.open (widget.id, widget.icon);
		}
	}
}


//
// animation stuff
//

var dialogAnimation = {startTime:0, duration:250, from:0, to:0, doframe:null, timer:null};

function limit_3 (a, b, c) {
    return a < b ? b : (a > c ? c : a);
}

function computeNextFloat (from, to, ease) {
    return from + (to - from) * ease;
}

function setupDialogAnimation (duration, from, to)
{
	var timeNow = (new Date).getTime();

	dialogAnimation.startTime = timeNow - 13; // set it back one frame.
	
	dialogAnimation.from = from;
	dialogAnimation.to = to;
	dialogAnimation.duration = duration;
	
	if (dialogAnimation.timer != null)
	{
		clearInterval (dialogAnimation.timer);
		dialogAnimation.timer = null;
	}
	dialogAnimation.doframe = dialogAnimationDoFrame;
	dialogAnimation.timer = setInterval (animate, 13, dialogAnimation);
	animate(dialogAnimation);
}

function animate (animation) {
	var T;
	var ease;
	var time  = (new Date).getTime();
	var now;
	var done = false;
		
	T = limit_3(time - animation.startTime, 0, animation.duration);
	ease = 0.5 - (0.5 * Math.cos(Math.PI * T / animation.duration));

	if (T >= animation.duration)
	{
		now = animation.to;
		clearInterval (animation.timer);
		animation.timer = null;
		done = true;
	}
	else
	{
		now = computeNextFloat(animation.from, animation.to, ease);
	}
		
	animation.doframe(animation, now, done);
}

function dialogAnimationDoFrame (animation, now, done)
{
	dialog.setAlpha (now);
	
	if (done && animation.to == 0)
	{
		dialog.cancel();
		dialog = null;
	}	
}

//
// dialog class
//
function Dialog (firstLineText, secondLineText, icon_url)
{
	var div = document.createElement('div');
	div.setAttribute('id', 'dialog-background');
	div.setAttribute('class', 'dialog-background');
	
	div.style.height = curr_middle_height + 2 + "px";
	
	// add the icon
	var img = document.createElement('img');
	img.width = '58';
	img.height = '58'
	img.setAttribute ('onerror', 'iconFailedToLoadDialog(event, this);');
	img.src = icon_url;
	img.setAttribute ('class', 'dialog-icon');
	div.appendChild (img);
	
	// add the first line	
	var text_div = document.createElement('div');
	text_div.innerText = firstLineText;
	text_div.setAttribute ('class', 'dialog-text dialog-first-line');
	div.appendChild (text_div);

	// add the second line	
	text_div = document.createElement('div');
	text_div.innerText = secondLineText;
	text_div.setAttribute ('class', 'dialog-text');
	div.appendChild (text_div);	
	
	// add the buttons
	
	// Cancel button
	var button_div = document.createElement('div');
	button_div.setAttribute('id', 'dialog-cancel-button');
	button_div.setAttribute('class', 'dialog-button');
	div.appendChild (button_div);
	createDialogButton (button_div, getLocalizedString('Cancel'), handleDialogCancel, 66);
	
	// OK button
	button_div = document.createElement('div');
	button_div.setAttribute('id', 'dialog-ok-button');
	button_div.setAttribute('class', 'dialog-button');
	div.appendChild (button_div);
	createDialogButton (button_div, getLocalizedString('OK'), handleDialogOK, 66);
	
	document.body.appendChild(div);
	this.background = div;	
}

Dialog.prototype.refresh = function () {
	this.background.style.height = curr_middle_height + 2 + "px";
}

Dialog.prototype.cancel = function () {
	document.body.removeChild (this.background);
	enableSortPopup (true);
}

Dialog.prototype.setAlpha = function (alpha) {
	this.background.style.opacity = alpha;
}


function handleDialogCancel ()
{
	setupDialogAnimation (175, 1, 0);
}

function handleDialogOK ()
{
	if (window.widgetManager)
	{
		var obj = allTheWidgets[dialog.widgetIndex];
		widgetManager.deleteWidget (obj.id);
	}
	else
	{
		deleteWidget (allTheWidgets[dialog.widgetIndex].id, true);
		//setupDialogAnimation (175, 1, 0);
		
	}
}